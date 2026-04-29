package io.castellum.supplychain;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import java.io.FileReader;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class SbomPluginPresenceTest {
    @Test
    void cyclonedxPluginBoundToPackagePhase() throws Exception {
        Path pom = Paths.get(System.getProperty("user.dir"), "pom.xml").toAbsolutePath();
        // Test runs in backend/ working dir; pom.xml is sibling.
        if (!pom.toFile().exists()) {
            // Some CI invocations run from repo root; fall back.
            pom = Paths.get(System.getProperty("user.dir"), "backend", "pom.xml").toAbsolutePath();
        }
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new FileReader(pom.toFile())));
        XPath xp = XPathFactory.newInstance().newXPath();

        String groupId = (String) xp.evaluate(
            "//build/plugins/plugin[artifactId='cyclonedx-maven-plugin']/groupId",
            doc, XPathConstants.STRING);
        assertEquals("org.cyclonedx", groupId, "cyclonedx-maven-plugin must be declared with groupId org.cyclonedx");

        NodeList phases = (NodeList) xp.evaluate(
            "//build/plugins/plugin[artifactId='cyclonedx-maven-plugin']/executions/execution/phase",
            doc, XPathConstants.NODESET);
        boolean foundPackage = false;
        for (int i = 0; i < phases.getLength(); i++) {
            if ("package".equals(phases.item(i).getTextContent().trim())) foundPackage = true;
        }
        assertTrue(foundPackage, "cyclonedx-maven-plugin must be bound to the 'package' phase");
    }
}
