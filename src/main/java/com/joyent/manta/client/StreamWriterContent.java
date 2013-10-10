/*
 * Copyright (c) 2013, Certusoft, Inc. All Rights Reserved.
 */
package com.joyent.manta.client;

import java.io.IOException;
import java.io.OutputStream;

import com.google.api.client.http.HttpContent;

/**
 * HttpContent implementation that wraps a StreamWriter.
 * 
 * @author headw01
 */
public class StreamWriterContent implements HttpContent {
    private String encoding = null;
    private String contentType;
    private StreamWriter writer;

    public StreamWriterContent(String contentType, StreamWriter writer) {
        this.contentType = contentType;
        this.writer = writer;
    }

    @Override
    public void writeTo(OutputStream out) throws IOException {
        if (null != out) {
            if (null != writer) {
                writer.write(out);
            }
            out.flush();
        }
    }

    @Override
    public boolean retrySupported() {
        return false;
    }

    @Override
    public String getType() {
        return contentType;
    }

    @Override
    public long getLength() throws IOException {
        return -1;
    }

    @Override
    public String getEncoding() {
        return encoding;
    }
    
    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }
}