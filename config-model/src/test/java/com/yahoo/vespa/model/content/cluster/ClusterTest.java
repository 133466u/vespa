// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.model.content.cluster;

import com.yahoo.config.application.api.ApplicationPackage;
import com.yahoo.config.model.test.MockApplicationPackage;
import com.yahoo.config.model.test.TestDriver;
import com.yahoo.vespa.config.search.core.PartitionsConfig;
import com.yahoo.vespa.config.search.core.ProtonConfig;
import com.yahoo.vespa.model.content.Content;
import com.yahoo.vespa.model.search.Dispatch;
import com.yahoo.vespa.model.search.IndexedSearchCluster;
import com.yahoo.vespa.model.test.utils.ApplicationPackageUtils;
import org.junit.Test;

import java.util.List;

import static com.yahoo.config.model.test.TestUtil.joinLines;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Simon Thoresen Hult
 */
public class ClusterTest {

    @Test
    public void requireThatContentSearchIsApplied() {
        ContentCluster cluster = newContentCluster(joinLines("<search>",
                "  <query-timeout>1.1</query-timeout>",
                "  <visibility-delay>2.3</visibility-delay>",
                "</search>"));
        IndexedSearchCluster searchCluster = cluster.getSearch().getIndexed();
        assertNotNull(searchCluster);
        assertEquals(1.1, searchCluster.getQueryTimeout(), 1E-6);
        assertEquals(2.3, searchCluster.getVisibilityDelay(), 1E-6);
        ProtonConfig proton = getProtonConfig(cluster);
        assertEquals(searchCluster.getVisibilityDelay(), proton.documentdb(0).visibilitydelay(), 1E-6);
    }

    @Test
    public void requireThatSearchCoverageIsApplied() {
        ContentCluster cluster = newContentCluster(joinLines("<search>",
                "  <coverage>",
                "    <minimum>0.11</minimum>",
                "    <min-wait-after-coverage-factor>0.23</min-wait-after-coverage-factor>",
                "    <max-wait-after-coverage-factor>0.58</max-wait-after-coverage-factor>",
                "  </coverage>",
                "</search>"));
        assertEquals(1, cluster.getSearch().getIndexed().getTLDs().size());
        for (Dispatch tld : cluster.getSearch().getIndexed().getTLDs()) {
            PartitionsConfig.Builder builder = new PartitionsConfig.Builder();
            tld.getConfig(builder);
            PartitionsConfig config = new PartitionsConfig(builder);
            assertEquals(11.0, config.dataset(0).minimal_searchcoverage(), 1E-6);
            assertEquals(0.23, config.dataset(0).higher_coverage_minsearchwait(), 1E-6);
            assertEquals(0.58, config.dataset(0).higher_coverage_maxsearchwait(), 1E-6);
            assertEquals(2, config.dataset(0).searchablecopies());
            assertTrue(config.dataset(0).useroundrobinforfixedrow());
        }
    }

    @Test
    public void requireThatDispatchTuningIsApplied()  {
        ContentCluster cluster = newContentCluster(joinLines("<search>", "</search>"),
                joinLines("<tuning>",
                        "</tuning>"));
        assertEquals(1, cluster.getSearch().getIndexed().getTLDs().size());
        for (Dispatch tld : cluster.getSearch().getIndexed().getTLDs()) {
            PartitionsConfig.Builder builder = new PartitionsConfig.Builder();
            tld.getConfig(builder);
            PartitionsConfig config = new PartitionsConfig(builder);
            assertEquals(2, config.dataset(0).searchablecopies());
            assertTrue(config.dataset(0).useroundrobinforfixedrow());
        }
    }

    @Test
    public void requireThatVisibilityDelayIsZeroForGlobalDocumentType() {
        ContentCluster cluster = newContentCluster(joinLines("<search>",
                "  <visibility-delay>2.3</visibility-delay>",
                "</search>"), true);
        ProtonConfig proton = getProtonConfig(cluster);
        assertEquals(0.0, proton.documentdb(0).visibilitydelay(), 1E-6);
    }

    private static ContentCluster newContentCluster(String contentSearchXml) {
        return newContentCluster(contentSearchXml, "", false);
    }

    private static ContentCluster newContentCluster(String contentSearchXml, String searchNodeTuningXml) {
        return newContentCluster(contentSearchXml, searchNodeTuningXml, false);
    }

    private static ContentCluster newContentCluster(String contentSearchXml, boolean globalDocType) {
        return newContentCluster(contentSearchXml, "", globalDocType);
    }

    private static ContentCluster newContentCluster(String contentSearchXml, String searchNodeTuningXml, boolean globalDocType) {
        ApplicationPackage app = new MockApplicationPackage.Builder()
                .withHosts(joinLines(
                        "<hosts>",
                        "  <host name='localhost'><alias>my_host</alias></host>",
                        "</hosts>"))
                .withServices(joinLines(
                        "<services version='1.0'>",
                        "  <admin version='2.0'>",
                        "    <adminserver hostalias='my_host' />",
                        "  </admin>",
                        "<container id='foo' version='1.0'>",
                        "  <search />",
                        "  <nodes><node hostalias='my_host' /></nodes>",
                        "</container>",
                        "  <content version='1.0'>",
                        "    <redundancy>3</redundancy>",
                        "    <documents>",
                        "    " + getDocumentXml(globalDocType),
                        "    </documents>",
                        "    <engine>",
                        "      <proton>",
                        "        <searchable-copies>2</searchable-copies>",
                        searchNodeTuningXml,
                        "      </proton>",
                        "    </engine>",
                        "    <group>",
                        "      <node hostalias='my_host' distribution-key='0' />",
                        "    </group>",
                        contentSearchXml,
                        "  </content>",
                        "</services>"))
                .withSearchDefinitions(ApplicationPackageUtils.generateSearchDefinition("my_document"))
                .build();
        List<Content> contents = new TestDriver().buildModel(app).getConfigModels(Content.class);
        assertEquals(1, contents.size());
        return contents.get(0).getCluster();
    }

    private static String getDocumentXml(boolean globalDocType) {
        return "<document mode='index' type='my_document' " + (globalDocType ? "global='true' " : "") + "/>";
    }

    private static ProtonConfig getProtonConfig(ContentCluster cluster) {
        ProtonConfig.Builder builder = new ProtonConfig.Builder();
        cluster.getSearch().getConfig(builder);
        return new ProtonConfig(builder);
    }

}
