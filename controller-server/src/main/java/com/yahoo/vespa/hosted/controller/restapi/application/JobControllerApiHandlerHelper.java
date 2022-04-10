// Copyright Yahoo. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.controller.restapi.application;

import com.yahoo.config.application.api.DeploymentSpec;
import com.yahoo.config.application.api.DeploymentSpec.ChangeBlocker;
import com.yahoo.config.provision.ApplicationId;
import com.yahoo.container.jdisc.HttpRequest;
import com.yahoo.container.jdisc.HttpResponse;
import com.yahoo.restapi.MessageResponse;
import com.yahoo.restapi.SlimeJsonResponse;
import com.yahoo.slime.ArrayTraverser;
import com.yahoo.slime.Cursor;
import com.yahoo.slime.Slime;
import com.yahoo.slime.SlimeUtils;
import com.yahoo.text.Text;
import com.yahoo.vespa.hosted.controller.Application;
import com.yahoo.vespa.hosted.controller.Controller;
import com.yahoo.vespa.hosted.controller.NotExistsException;
import com.yahoo.vespa.hosted.controller.api.integration.LogEntry;
import com.yahoo.vespa.hosted.controller.api.integration.deployment.ApplicationVersion;
import com.yahoo.vespa.hosted.controller.api.integration.deployment.JobId;
import com.yahoo.vespa.hosted.controller.api.integration.deployment.JobType;
import com.yahoo.vespa.hosted.controller.api.integration.deployment.RunId;
import com.yahoo.vespa.hosted.controller.api.integration.deployment.SourceRevision;
import com.yahoo.vespa.hosted.controller.application.Change;
import com.yahoo.vespa.hosted.controller.application.TenantAndApplicationId;
import com.yahoo.vespa.hosted.controller.application.pkg.ApplicationPackage;
import com.yahoo.vespa.hosted.controller.deployment.ConvergenceSummary;
import com.yahoo.vespa.hosted.controller.deployment.DeploymentStatus;
import com.yahoo.vespa.hosted.controller.deployment.JobController;
import com.yahoo.vespa.hosted.controller.deployment.JobStatus;
import com.yahoo.vespa.hosted.controller.deployment.Run;
import com.yahoo.vespa.hosted.controller.deployment.RunLog;
import com.yahoo.vespa.hosted.controller.deployment.RunStatus;
import com.yahoo.vespa.hosted.controller.deployment.Step;
import com.yahoo.vespa.hosted.controller.deployment.Versions;
import com.yahoo.vespa.hosted.controller.versions.VersionStatus;
import com.yahoo.vespa.hosted.controller.versions.VespaVersion;

import java.net.URI;
import java.time.Instant;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.yahoo.config.application.api.DeploymentSpec.UpgradePolicy.canary;
import static com.yahoo.vespa.hosted.controller.deployment.Step.Status.succeeded;
import static com.yahoo.vespa.hosted.controller.deployment.Step.installInitialReal;
import static com.yahoo.vespa.hosted.controller.deployment.Step.installReal;
import static com.yahoo.vespa.hosted.controller.versions.VespaVersion.Confidence.broken;
import static com.yahoo.vespa.hosted.controller.versions.VespaVersion.Confidence.normal;
import static java.util.Comparator.reverseOrder;

/**
 * Implements the REST API for the job controller delegated from the Application API.
 *
 * @see JobController
 * @see ApplicationApiHandler
 *
 * @author smorgrav
 * @author jonmv
 */
class JobControllerApiHandlerHelper {

    /**
     * @return Response with all job types that have recorded runs for the application _and_ the status for the last run of that type
     */
    static HttpResponse jobTypeResponse(Controller controller, ApplicationId id, URI baseUriForJobs) {
        Slime slime = new Slime();
        Cursor responseObject = slime.setObject();

        Cursor jobsArray = responseObject.setArray("deployment");
        Arrays.stream(JobType.values())
              .filter(type -> type.environment().isManuallyDeployed())
              .map(devType -> new JobId(id, devType))
              .forEach(job -> {
                  Collection<Run> runs = controller.jobController().runs(job).descendingMap().values();
                  if (runs.isEmpty())
                      return;

                  Cursor jobObject = jobsArray.addObject();
                  jobObject.setString("jobName", job.type().jobName());
                  toSlime(jobObject.setArray("runs"), runs, 10, baseUriForJobs);
              });

        return new SlimeJsonResponse(slime);
    }

    /** Returns a response with the runs for the given job type. */
    static HttpResponse runResponse(Map<RunId, Run> runs, Optional<String> limitStr, URI baseUriForJobType) {
        Slime slime = new Slime();
        Cursor cursor = slime.setObject();

        int limit = limitStr.map(Integer::parseInt).orElse(Integer.MAX_VALUE);
        toSlime(cursor.setArray("runs"), runs.values(), limit, baseUriForJobType);

        return new SlimeJsonResponse(slime);
    }

    /**
     * @return Response with logs from a single run
     */
    static HttpResponse runDetailsResponse(JobController jobController, RunId runId, String after) {
        Slime slime = new Slime();
        Cursor detailsObject = slime.setObject();

        Run run = jobController.run(runId)
                               .orElseThrow(() -> new IllegalStateException("Unknown run '" + runId + "'"));
        detailsObject.setBool("active", ! run.hasEnded());
        detailsObject.setString("status", nameOf(run.status()));
        try {
            jobController.updateTestLog(runId);
            jobController.updateVespaLog(runId);
        }
        catch (RuntimeException ignored) { } // Return response when this fails, which it does when, e.g., logserver is booting.

        RunLog runLog = (after == null ? jobController.details(runId) : jobController.details(runId, Long.parseLong(after)))
                .orElseThrow(() -> new NotExistsException(Text.format(
                        "No run details exist for application: %s, job type: %s, number: %d",
                        runId.application().toShortString(), runId.type().jobName(), runId.number())));

        Cursor logObject = detailsObject.setObject("log");
        for (Step step : Step.values()) {
            if ( ! runLog.get(step).isEmpty())
                toSlime(logObject.setArray(step.name()), runLog.get(step));
        }
        runLog.lastId().ifPresent(id -> detailsObject.setLong("lastId", id));

        Cursor stepsObject = detailsObject.setObject("steps");
        run.steps().forEach((step, info) -> {
            Cursor stepCursor = stepsObject.setObject(step.name());
            stepCursor.setString("status", info.status().name());
            info.startTime().ifPresent(startTime -> stepCursor.setLong("startMillis", startTime.toEpochMilli()));
            run.convergenceSummary().ifPresent(summary -> {
                // If initial installation never succeeded, but is part of the job, summary concerns it.
                // If initial succeeded, or is not part of this job, summary concerns upgrade installation.
                if (   step == installInitialReal && info.status() != succeeded
                    || step == installReal && run.stepStatus(installInitialReal).map(status -> status == succeeded).orElse(true))
                    toSlime(stepCursor.setObject("convergence"), summary);
            });
        });

        // If a test report is available, include it in the response.
        Optional<String> testReport = jobController.getTestReports(runId);
        testReport.map(SlimeUtils::jsonToSlime)
                  .map(Slime::get)
                  .ifPresent(reportArrayCursor -> {
                      reportArrayCursor.traverse((ArrayTraverser) (i, reportCursor) -> {
                          if (i > 0) return;
                          SlimeUtils.copyObject(reportCursor, detailsObject.setObject("testReport"));
                      });
                      SlimeUtils.copyArray(reportArrayCursor, detailsObject.setArray("testReports"));
                  });

        return new SlimeJsonResponse(slime);
    }

    private static void toSlime(Cursor summaryObject, ConvergenceSummary summary) {
        summaryObject.setLong("nodes", summary.nodes());
        summaryObject.setLong("down", summary.down());
        summaryObject.setLong("needPlatformUpgrade", summary.needPlatformUpgrade());
        summaryObject.setLong("upgrading", summary.upgradingPlatform());
        summaryObject.setLong("needReboot", summary.needReboot());
        summaryObject.setLong("rebooting", summary.rebooting());
        summaryObject.setLong("needRestart", summary.needRestart());
        summaryObject.setLong("restarting", summary.restarting());
        summaryObject.setLong("upgradingOs", summary.upgradingOs());
        summaryObject.setLong("upgradingFirmware", summary.upgradingFirmware());
        summaryObject.setLong("services", summary.services());
        summaryObject.setLong("needNewConfig", summary.needNewConfig());
        summaryObject.setLong("retiring", summary.retiring());
    }

    private static void toSlime(Cursor entryArray, List<LogEntry> entries) {
        entries.forEach(entry -> toSlime(entryArray.addObject(), entry));
    }

    private static void toSlime(Cursor entryObject, LogEntry entry) {
        entryObject.setLong("at", entry.at().toEpochMilli());
        entryObject.setString("type", entry.type().name());
        entryObject.setString("message", entry.message());
    }

    /**
     * Unpack payload and submit to job controller. Defaults instance to 'default' and renders the
     * application version on success.
     *
     * @return Response with the new application version
     */
    static HttpResponse submitResponse(JobController jobController, String tenant, String application,
                                       Optional<SourceRevision> sourceRevision, Optional<String> authorEmail,
                                       Optional<String> sourceUrl, Optional<String> description, int risk, long projectId,
                                       ApplicationPackage applicationPackage, byte[] testPackage) {
        ApplicationVersion version = jobController.submit(TenantAndApplicationId.from(tenant, application), sourceRevision, authorEmail,
                                                          sourceUrl, projectId, applicationPackage, testPackage, description, risk);

        return new MessageResponse(version.toString());
    }

    /** Aborts any job of the given type. */
    static HttpResponse abortJobResponse(JobController jobs, HttpRequest request, ApplicationId id, JobType type) {
        Slime slime = new Slime();
        Cursor responseObject = slime.setObject();
        Optional<Run> run = jobs.last(id, type).flatMap(last -> jobs.active(last.id()));
        if (run.isPresent()) {
            jobs.abort(run.get().id(), "aborted by " + request.getJDiscRequest().getUserPrincipal());
            responseObject.setString("message", "Aborting " + run.get().id());
        }
        else
            responseObject.setString("message", "Nothing to abort.");
        return new SlimeJsonResponse(slime);
    }

    private static String nameOf(RunStatus status) {
        switch (status) {
            case reset:                      // This means the run will reset and keep running.
            case running:                    return "running";
            case aborted:                    return "aborted";
            case error:                      return "error";
            case testFailure:                return "testFailure";
            case endpointCertificateTimeout: return "endpointCertificateTimeout";
            case nodeAllocationFailure:      return "nodeAllocationFailure";
            case installationFailed:         return "installationFailed";
            case deploymentFailed:           return "deploymentFailed";
            case success:                    return "success";
            default:                         throw new IllegalArgumentException("Unexpected status '" + status + "'");
        }
    }

    /**
     * Returns response with all job types that have recorded runs for the application
     * _and_ the status for the last run of that type
     */
    static HttpResponse overviewResponse(Controller controller, TenantAndApplicationId id, URI baseUriForDeployments) {
        Application application = controller.applications().requireApplication(id);
        DeploymentStatus status = controller.jobController().deploymentStatus(application);

        Slime slime = new Slime();
        Cursor responseObject = slime.setObject();
        responseObject.setString("tenant", id.tenant().value());
        responseObject.setString("application", id.application().value());
        application.projectId().ifPresent(projectId -> responseObject.setLong("projectId", projectId));

        Map<JobId, List<DeploymentStatus.Job>> jobsToRun = status.jobsToRun();
        Cursor stepsArray = responseObject.setArray("steps");
        VersionStatus versionStatus = controller.readVersionStatus();
        for (DeploymentStatus.StepStatus stepStatus : status.allSteps()) {
            Change change = status.application().require(stepStatus.instance()).change();
            Cursor stepObject = stepsArray.addObject();
            stepObject.setString("type", stepStatus.type().name());
            stepStatus.dependencies().stream()
                      .map(status.allSteps()::indexOf)
                      .forEach(stepObject.setArray("dependencies")::addLong);
            stepObject.setBool("declared", stepStatus.isDeclared());
            stepObject.setString("instance", stepStatus.instance().value());

            // TODO: recursively search dependents for what is the relevant partial change when this is a delay step ...
            Optional<Instant> readyAt = stepStatus.job().map(jobsToRun::get).map(jobs -> jobs.get(0).readyAt())
                                                  .orElse(stepStatus.readyAt(change));
            readyAt.ifPresent(ready -> stepObject.setLong("readyAt", ready.toEpochMilli()));
            readyAt.filter(controller.clock().instant()::isBefore)
                   .ifPresent(until -> stepObject.setLong("delayedUntil", until.toEpochMilli()));
            stepStatus.pausedUntil().ifPresent(until -> stepObject.setLong("pausedUntil", until.toEpochMilli()));
            stepStatus.coolingDownUntil(change).ifPresent(until -> stepObject.setLong("coolingDownUntil", until.toEpochMilli()));
            stepStatus.blockedUntil(Change.of(controller.systemVersion(versionStatus))) // Dummy version — just anything with a platform.
                      .ifPresent(until -> stepObject.setLong("platformBlockedUntil", until.toEpochMilli()));
            application.revisions().last().map(Change::of).flatMap(stepStatus::blockedUntil) // Dummy version — just anything with an application.
                       .ifPresent(until -> stepObject.setLong("applicationBlockedUntil", until.toEpochMilli()));

            if (stepStatus.type() == DeploymentStatus.StepType.delay)
                stepStatus.completedAt(change).ifPresent(completed -> stepObject.setLong("completedAt", completed.toEpochMilli()));

            if (stepStatus.type() == DeploymentStatus.StepType.instance) {
                Cursor deployingObject = stepObject.setObject("deploying");
                if ( ! change.isEmpty()) {
                    change.platform().ifPresent(version -> deployingObject.setString("platform", version.toFullString()));
                    change.application().ifPresent(version -> toSlime(deployingObject.setObject("application"), version));
                }

                Cursor latestVersionsObject = stepObject.setObject("latestVersions");
                List<ChangeBlocker> blockers = application.deploymentSpec().requireInstance(stepStatus.instance()).changeBlocker();
                var deployments = application.require(stepStatus.instance()).productionDeployments().values();
                List<VespaVersion> availablePlatforms = availablePlatforms(versionStatus.versions(),
                                                                           application.deploymentSpec().requireInstance(stepStatus.instance()).upgradePolicy());
                if ( ! availablePlatforms.isEmpty()) {
                    Cursor latestPlatformObject = latestVersionsObject.setObject("platform");
                    VespaVersion latestPlatform = availablePlatforms.get(0);
                    latestPlatformObject.setString("platform", latestPlatform.versionNumber().toFullString());
                    latestPlatformObject.setLong("at", latestPlatform.committedAt().toEpochMilli());
                    latestPlatformObject.setBool("upgrade",    change.platform().map(latestPlatform.versionNumber()::isAfter).orElse(true) && deployments.isEmpty()
                                                            || deployments.stream().anyMatch(deployment -> deployment.version().isBefore(latestPlatform.versionNumber())));

                    Cursor availableArray = latestPlatformObject.setArray("available");
                    for (VespaVersion available : availablePlatforms) {
                        if (   deployments.stream().anyMatch(deployment -> deployment.version().isAfter(available.versionNumber()))
                            || deployments.stream().noneMatch(deployment -> deployment.version().isBefore(available.versionNumber())) && ! deployments.isEmpty()
                            || status.hasCompleted(stepStatus.instance(), Change.of(available.versionNumber()))
                            || change.platform().map(available.versionNumber()::compareTo).orElse(1) <= 0)
                            break;

                        availableArray.addObject().setString("platform", available.versionNumber().toFullString());
                    }
                    change.platform().ifPresent(version -> availableArray.addObject().setString("platform", version.toFullString()));
                    toSlime(latestPlatformObject.setArray("blockers"), blockers.stream().filter(ChangeBlocker::blocksVersions));
                }
                List<ApplicationVersion> availableApplications = new ArrayList<>(application.revisions().deployable(false));
                if ( ! availableApplications.isEmpty()) {
                    var latestApplication = availableApplications.get(0);
                    Cursor latestApplicationObject = latestVersionsObject.setObject("application");
                    toSlime(latestApplicationObject.setObject("application"), latestApplication);
                    latestApplicationObject.setLong("at", latestApplication.buildTime().orElse(Instant.EPOCH).toEpochMilli());
                    latestApplicationObject.setBool("upgrade",    change.application().map(latestApplication::compareTo).orElse(1) > 0 && deployments.isEmpty()
                                                               || deployments.stream().anyMatch(deployment -> deployment.applicationVersion().compareTo(latestApplication) < 0));

                    Cursor availableArray = latestApplicationObject.setArray("available");
                    for (ApplicationVersion available : availableApplications) {
                        if (   deployments.stream().anyMatch(deployment -> deployment.applicationVersion().compareTo(available) > 0)
                            || deployments.stream().noneMatch(deployment -> deployment.applicationVersion().compareTo(available) < 0) && ! deployments.isEmpty()
                            || status.hasCompleted(stepStatus.instance(), Change.of(available))
                            || change.application().map(available::compareTo).orElse(1) <= 0)
                            break;

                        toSlime(availableArray.addObject().setObject("application"), available);
                    }
                    change.application().ifPresent(version -> toSlime(availableArray.addObject().setObject("application"), version));
                    toSlime(latestApplicationObject.setArray("blockers"), blockers.stream().filter(ChangeBlocker::blocksRevisions));
                }
            }

            stepStatus.job().ifPresent(job -> {
                stepObject.setString("jobName", job.type().jobName());
                URI baseUriForJob = baseUriForDeployments.resolve(baseUriForDeployments.getPath() +
                                                                     "/../instance/" + job.application().instance().value() +
                                                                     "/job/" + job.type().jobName()).normalize();
                stepObject.setString("url", baseUriForJob.toString());
                stepObject.setString("environment", job.type().environment().value());
                stepObject.setString("region", job.type().zone(controller.system()).value());

                if (job.type().isProduction() && job.type().isDeployment()) {
                    status.deploymentFor(job).ifPresent(deployment -> {
                        stepObject.setString("currentPlatform", deployment.version().toFullString());
                        toSlime(stepObject.setObject("currentApplication"), deployment.applicationVersion());
                    });
                }

                JobStatus jobStatus = status.jobs().get(job).get();
                Cursor toRunArray = stepObject.setArray("toRun");
                for (DeploymentStatus.Job versions : jobsToRun.getOrDefault(job, List.of())) {
                    boolean running = jobStatus.lastTriggered()
                                               .map(run ->    jobStatus.isRunning()
                                                           && versions.versions().targetsMatch(run.versions())
                                                           && (job.type().isProduction() || versions.versions().sourcesMatchIfPresent(run.versions())))
                                               .orElse(false);
                    if (running)
                        continue; // Run will be contained in the "runs" array.

                    Cursor runObject = toRunArray.addObject();
                    toSlime(runObject.setObject("versions"), versions.versions());
                }

                toSlime(stepObject.setArray("runs"), jobStatus.runs().descendingMap().values(), 10, baseUriForJob);
            });
        }

        Cursor buildsArray = responseObject.setArray("builds");
        application.revisions().withPackage().stream().sorted(reverseOrder()).forEach(version -> toSlime(buildsArray.addObject(), version));

        return new SlimeJsonResponse(slime);
    }

    static void toSlime(Cursor versionObject, ApplicationVersion version) {
        version.buildNumber().ifPresent(id -> versionObject.setLong("build", id));
        version.compileVersion().ifPresent(platform -> versionObject.setString("compileVersion", platform.toFullString()));
        version.sourceUrl().ifPresent(url -> versionObject.setString("sourceUrl", url));
        version.commit().ifPresent(commit -> versionObject.setString("commit", commit));
    }

    private static void toSlime(Cursor versionsObject, Versions versions) {
        versionsObject.setString("targetPlatform", versions.targetPlatform().toFullString());
        toSlime(versionsObject.setObject("targetApplication"), versions.targetApplication());
        versions.sourcePlatform().ifPresent(platform -> versionsObject.setString("sourcePlatform", platform.toFullString()));
        versions.sourceApplication().ifPresent(application -> toSlime(versionsObject.setObject("sourceApplication"), application));
    }

    private static void toSlime(Cursor blockersArray, Stream<ChangeBlocker> blockers) {
        blockers.forEach(blocker -> {
            Cursor blockerObject = blockersArray.addObject();
            blocker.window().days().stream()
                   .map(day -> day.getDisplayName(TextStyle.SHORT, Locale.ENGLISH))
                   .forEach(blockerObject.setArray("days")::addString);
            blocker.window().hours()
                   .forEach(blockerObject.setArray("hours")::addLong);
            blockerObject.setString("zone", blocker.window().zone().toString());
        });
    }

    private static List<VespaVersion> availablePlatforms(List<VespaVersion> versions, DeploymentSpec.UpgradePolicy policy) {
        int i;
        for (i = versions.size(); i-- > 0; )
            if (versions.get(i).isSystemVersion())
                break;

        if (i < 0)
            return List.of();

        List<VespaVersion> candidates = new ArrayList<>();
        VespaVersion.Confidence required = policy == canary ? broken : normal;
        for (int j = i; j >= 0; j--)
            if (versions.get(j).confidence().equalOrHigherThan(required))
                candidates.add(versions.get(j));

        if (candidates.isEmpty())
            candidates.add(versions.get(i));

        return candidates;
    }

    private static void toSlime(Cursor runsArray, Collection<Run> runs, int limit, URI baseUriForJob) {
        runs.stream().limit(limit).forEach(run -> {
            Cursor runObject = runsArray.addObject();
            runObject.setLong("id", run.id().number());
            runObject.setString("url", baseUriForJob.resolve(baseUriForJob.getPath() + "/run/" + run.id().number()).toString());
            runObject.setLong("start", run.start().toEpochMilli());
            run.end().ifPresent(end -> runObject.setLong("end", end.toEpochMilli()));
            runObject.setString("status", run.status().name());
            toSlime(runObject.setObject("versions"), run.versions());
            Cursor runStepsArray = runObject.setArray("steps");
            run.steps().forEach((step, info) -> {
                Cursor runStepObject = runStepsArray.addObject();
                runStepObject.setString("name", step.name());
                runStepObject.setString("status", info.status().name());
            });
        });
    }

}
