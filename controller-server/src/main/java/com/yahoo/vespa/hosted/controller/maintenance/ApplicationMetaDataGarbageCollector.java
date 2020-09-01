package com.yahoo.vespa.hosted.controller.maintenance;

import com.yahoo.vespa.hosted.controller.Controller;

import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ApplicationMetaDataGarbageCollector extends ControllerMaintainer {

    private static final Logger log = Logger.getLogger(ApplicationMetaDataGarbageCollector.class.getName());

    public ApplicationMetaDataGarbageCollector(Controller controller) {
        super(controller, Duration.ofHours(12));
    }

    @Override
    protected boolean maintain() {
        try {
            controller().applications().applicationStore().pruneMeta(controller().clock().instant().minus(Duration.ofDays(365)));
            return true;
        }
        catch (Exception e) {
            log.log(Level.WARNING, "Exception pruning old application meta data", e);
            return false;
        }
    }

}
