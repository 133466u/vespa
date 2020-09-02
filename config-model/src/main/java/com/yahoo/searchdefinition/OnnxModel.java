// Copyright Verizon Media. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.searchdefinition;

import com.yahoo.config.FileReference;
import com.yahoo.vespa.model.AbstractService;
import com.yahoo.vespa.model.utils.FileSender;

import java.util.Collection;
import java.util.Objects;

/**
 * A global ONNX model distributed using file distribution, similar to ranking constants.
 *
 * @author lesters
 */
public class OnnxModel {

    public enum PathType {FILE, URI};

    private final String name;
    private String path = null;
    private String fileReference = "";

    public PathType getPathType() {
        return pathType;
    }

    private PathType pathType = PathType.FILE;

    public OnnxModel(String name) {
        this.name = name;
    }

    public OnnxModel(String name, String fileName) {
        this(name);
        this.path = fileName;
        validate();
    }

    public void setFileName(String fileName) {
        Objects.requireNonNull(fileName, "Filename cannot be null");
        this.path = fileName;
        this.pathType = PathType.FILE;
    }

    public void setUri(String uri) {
        Objects.requireNonNull(uri, "uri cannot be null");
        this.path = uri;
        this.pathType = PathType.URI;
    }

    /** Initiate sending of this constant to some services over file distribution */
    public void sendTo(Collection<? extends AbstractService> services) {
        FileReference reference = (pathType == OnnxModel.PathType.FILE)
                                  ? FileSender.sendFileToServices(path, services)
                                  : FileSender.sendUriToServices(path, services);
        this.fileReference = reference.value();
    }

    public String getName() { return name; }
    public String getFileName() { return path; }
    public String getUri() { return path; }
    public String getFileReference() { return fileReference; }

    public void validate() {
        if (path == null || path.isEmpty())
            throw new IllegalArgumentException("ONNX models must have a file or uri.");
    }

    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("onnx-model '").append(name)
         .append(pathType == PathType.FILE ? "' from file '" : " from uri ").append(path)
         .append("' with ref '").append(fileReference)
         .append("'");
        return b.toString();
    }

}
