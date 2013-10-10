/*
 * Copyright (c) 2013, Certusoft, Inc. All Rights Reserved.
 */
package com.joyent.manta.client;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Writes 'something' to an OutputStream.  That 'something' can be generated at the time the write
 * is requested.<br />
 * 
 * <br />
 * For example:<br />
 * <pre>
 * MantaObject mantaObject = new MantaObject("/user/stor/foo");
 * mantaObject.setStreamWriter(
 *   new StreamWriter() {
 *     public void write(OutputStream out) throws IOException {
 *       out.write(UUID.randomUUID().toString().getBytes());
 *       out.flush();
 *     }
 *   }
 * );
 * 
 * MantaClient.newInstance(...).put(mantaObject);
 * </pre>
 * 
 * @author headw01
 *
 */
public interface StreamWriter {
    /**
     * Write something to the OutputStream.  It is probably a good idea 
     * to call <code>out.flush()</code> when you are done writing.
     * 
     * @param out
     * @throws IOException
     */
    void write(OutputStream out) throws IOException;
}