/**
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */
package com.joyent.manta.client;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;

import org.apache.commons.io.FileUtils;

import com.google.api.client.http.HttpHeaders;
import com.google.api.client.util.Key;
import com.google.common.io.ByteStreams;

/**
 * A Manta storage object.
 * <p>
 * I/O is performed via the getDataInputStream() and setDataInputStream() methods. Importantly, the stream isn't
 * automatically closed, specifically, the http connection remains open until the stream is closed -- so consumers must
 * call close() when done to avoid memory leaks. Example get usage:
 * </p>
 *
 * <pre>
 * MantaClient client = MantaClient.getInstance(...);
 * MantaObject object = client.get(&quot;/user/stor/foo&quot;);
 * // MantaUtils.inputStreamToString() closes the inputstream.
 * String data = MantaUtils.inputStreamToString(gotObject.getDataInputStream());
 * </pre>
 * <p>
 * Example put usage:
 * </p>
 *
 * <pre>
 * MantaClient client = MantaClient.getInstance(...);
 * MantaObject object = new MantaObject(&quot;user/stor/foo&quot;);
 * object.setHeader("durability-level", 3);
 * InputStream is = new FileInputStream(new File(TEST_FILE));
 * object.setDataInputStream(is);
 * client.put(object, null);
 * </pre>
 *
 * @author Yunong Xiao
 */
public class MantaObject implements Serializable {
    private static final long serialVersionUID = 1465638185667442505L;

    /**
     * Metadata names used by Manta.
     */
    public static final String DIRECTORY = "directory";

    /**
     * Manta directory header.
     */
    public static final String DIRECTORY_HEADER = "application/x-json-stream; type=directory";

    /**
     * JSON object metadata fields returned by {@link MantaClient}.listDir().
     */
    @Key("name")
    private String path_;

    @Key("size")
    private Long contentLength_;

    @Key("md5")
    private String contentMD5_;

    @Key("type")
    private String contentType_;

    @Key("etag")
    private String etag_;

    @Key("mtime")
    private String mtime_;

    /**
     * Other private members.
     */
    private File dataInputFile_;

    private InputStream dataInputStream_;

    private String dataInputString_;

    private StreamWriter streamWriter_;
    
    private HttpHeaders httpHeaders_;

    /**
     * Empty constructor for the JSON parser.
     */
    public MantaObject() {
    }

    /**
     * Creates a MantaObject.
     *
     * @param path
     *            The fully qualified path of the object in Manta. i.e. "/user/stor/path/to/some/file/or/dir".
     */
    public MantaObject(final String path) {
        this.path_ = path;
        this.httpHeaders_ = new HttpHeaders();
    }

    /**
     * Creates a MantaObject.
     *
     * @param path
     *            The fully qualified path of the object in Manta. i.e. "/user/stor/path/to/some/file/or/dir".
     * @param headers
     *            Optional {@link HttpHeaders}. Use this to set any additional headers on the Manta object. For the full
     *            list of Manta headers see the <a href="http://apidocs.joyent.com/manta/manta/">Manta API</a>.
     */
    public MantaObject(String path, HttpHeaders headers) {
        path_ = path;
        setHttpHeaders(headers);
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public final boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof MantaObject)) {
            return false;
        }
        final MantaObject other = (MantaObject) obj;
        if (this.contentLength_ == null) {
            if (other.contentLength_ != null) {
                return false;
            }
        }
        else if (!this.contentLength_.equals(other.contentLength_)) {
            return false;
        }
        if (contentMD5_ == null) {
            if (other.contentMD5_ != null)
                return false;
        }
        else if (!contentMD5_.equals(other.contentMD5_)) {
            return false;
        }
        if (contentType_ == null) {
            if (other.contentType_ != null) {
                return false;
            }
        }
        else if (!this.contentType_.equals(other.contentType_)) {
            return false;
        }
        if (this.dataInputFile_ == null) {
            if (other.dataInputFile_ != null) {
                return false;
            }
        }
        else if (!this.dataInputFile_.equals(other.dataInputFile_)) {
            return false;
        }
        if (streamWriter_ == null) {
            if (other.streamWriter_ != null) {
                return false;
            }
        }
        else if (!streamWriter_.equals(other.streamWriter_)) {
            return false;
        }
        if (dataInputStream_ == null) {
            if (other.dataInputStream_ != null) {
                return false;
            }
        }
        else if (!this.dataInputStream_.equals(other.dataInputStream_)) {
            return false;
        }
        if (this.dataInputString_ == null) {
            if (other.dataInputString_ != null) {
                return false;
            }
        }
        else if (!this.dataInputString_.equals(other.dataInputString_)) {
            return false;
        }
        if (this.etag_ == null) {
            if (other.etag_ != null) {
                return false;
            }
        }
        else if (!this.etag_.equals(other.etag_)) {
            return false;
        }
        if (this.httpHeaders_ == null) {
            if (other.httpHeaders_ != null) {
                return false;
            }
        }
        else if (!this.httpHeaders_.equals(other.httpHeaders_)) {
            return false;
        }
        if (this.mtime_ == null) {
            if (other.mtime_ != null) {
                return false;
            }
        }
        else if (!this.mtime_.equals(other.mtime_)) {
            return false;
        }
        if (this.path_ == null) {
            if (other.path_ != null) {
                return false;
            }
        }
        else if (!this.path_.equals(other.path_)) {
            return false;
        }
        return true;
    }

    /**
     * @return the size
     */
    public final Long getContentLength() {
        return this.contentLength_;
    }

    /**
     * @return the MD5
     */
    public final String getContentMD5() {
        return contentMD5_;
    }

    /**
     * @return the type
     */
    public final String getContentType() {
        return this.contentType_;
    }

    /**
     * Returns a {@link File} containing this object's data, if such a file has been provided. Otherwise returns null.
     *
     * @return the dataInputFile
     */
    public final File getDataInputFile() {
        return this.dataInputFile_;
    }

    public final void setStreamWriter(StreamWriter streamWriter) {
        this.streamWriter_ = streamWriter;
    }
    public final StreamWriter getStreamWriter() throws IOException {
        if (null == streamWriter_) {
            final InputStream dataInputStream = getDataInputStream();
            if (null != dataInputStream) {
                streamWriter_ = new StreamWriter() {
                    @Override
                    public void write(OutputStream out) throws IOException {
                        ByteStreams.copy(dataInputStream, out);
                    }
                };
            }
        }
        
        return streamWriter_;
    }
    
    /**
     * Returns an {@link InputStream} containing this object's data, or null if there is no data associated with this
     * object.
     *
     * @return the dataInputStream
     * @throws IOException
     *             If an IO exception has occured.
     */
    public final InputStream getDataInputStream() throws IOException {
        if (this.dataInputStream_ == null) {
            if (this.dataInputFile_ != null) {
                this.dataInputStream_ = new FileInputStream(this.dataInputFile_);
            } else if (this.dataInputString_ != null) {
                this.dataInputStream_ = new ByteArrayInputStream(this.dataInputString_.getBytes("UTF-8"));
            }
        }
        return this.dataInputStream_;
    }

    /**
     * Return the {@link String} containing this object's data. If the object's data is contained in the
     * {@link InputStream}, then the data is read from the {@link InputStream}, returned as this {@link String} and the
     * {@link InputStream} is closed. If the object's data is contained in a {@link File}, then the file is read back
     * into the {@link String} .
     *
     * @return the dataInputString
     * @throws IOException
     *             If an IO exception has occured.
     */
    public final String getDataInputString() throws IOException {
        if (this.dataInputString_ == null) {
            if (this.dataInputStream_ != null) {
                this.dataInputString_ = MantaUtils.inputStreamToString(this.dataInputStream_);
            } else if (this.dataInputFile_ != null) {
                this.dataInputString_ = FileUtils.readFileToString(this.dataInputFile_);
            }
        }
        return this.dataInputString_;
    }

    /**
     * @return the etag
     */
    public final String getEtag() {
        return this.etag_;
    }

    /**
     * This really just delegates to {@link HttpHeaders}.get.
     *
     * @param fieldName
     *            the custom header to get from the Manta object.
     * @return the value of the header.
     */
    public final Object getHeader(final String fieldName) {
        return this.httpHeaders_.get(fieldName);
    }

    /**
     * @return the httpHeaders
     */
    public final HttpHeaders getHttpHeaders() {
        return this.httpHeaders_;
    }

    /**
     * @return the mtime
     */
    public final String getMtime() {
        return this.mtime_;
    }

    /**
     * @return the path
     */
    public final String getPath() {
        return this.path_;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((contentLength_ == null) ? 0 : contentLength_.hashCode());
        result = prime * result + ((contentMD5_ == null) ? 0 : contentMD5_.hashCode());
        result = prime * result + ((contentType_ == null) ? 0 : contentType_.hashCode());
        result = prime * result + ((dataInputFile_ == null) ? 0 : dataInputFile_.hashCode());
        result = prime * result + ((dataInputStream_ == null) ? 0 : dataInputStream_.hashCode());
        result = prime * result + ((dataInputString_ == null) ? 0 : dataInputString_.hashCode());
        result = prime * result + ((etag_ == null) ? 0 : etag_.hashCode());
        result = prime * result + ((httpHeaders_ == null) ? 0 : httpHeaders_.hashCode());
        result = prime * result + ((mtime_ == null) ? 0 : mtime_.hashCode());
        result = prime * result + ((path_ == null) ? 0 : path_.hashCode());

        return result;
    }

    /**
     * @return whether this object is a Manta directory.
     */
    public final boolean isDirectory() {
        return this.contentType_.equals(DIRECTORY) || this.contentType_.equals(DIRECTORY_HEADER);
    }

    /**
     * @param dataInputFile
     *            the dataInputFile_ to set
     */
    public final void setDataInputFile(final File dataInputFile) {
        this.dataInputFile_ = dataInputFile;
    }

    /**
     * Sets the {@link InputStream} containing the data content of this object.
     *
     * @param dataInputStream
     *            the dataInputStream_ to set
     */
    public final void setDataInputStream(final InputStream dataInputStream) {
        this.dataInputStream_ = dataInputStream;
    }

    /**
     * @param dataInputString
     *            the dataInputString to set
     */
    public final void setDataInputString(final String dataInputString) {
        this.dataInputString_ = dataInputString;
    }

    /**
     * Sets custom headers on the Manta object. This really just delegates to setting the {@link HttpHeaders} object.
     * For the full list of Manta headers see the <a href="http://apidocs.joyent.com/manta/manta/">Manta API</a>.
     *
     * @param fieldName
     *            the field name.
     * @param value
     *            the field value.
     */
    public final void setHeader(final String fieldName, final Object value) {
        if (null == httpHeaders_) {
            httpHeaders_ = new HttpHeaders();
        }
        this.httpHeaders_.set(fieldName, value);
    }

    /**
     * Sets the {@link HttpHeaders} in this object. Note any previous headers will be lost. For the full list of Manta
     * headers see the <a href="http://apidocs.joyent.com/manta/manta/">Manta API</a>.
     *
     * @param httpHeaders
     *            the httpHeaders_ to set
     */
    public final void setHttpHeaders(final HttpHeaders httpHeaders) {
        this.httpHeaders_ = httpHeaders;
        extractMetadata(httpHeaders);
    }

    /**
     * Get the available Metadata out of the HttpHeaders.
     * @see path_
     * @see contentLength_
     * @see contentMD5_
     * @see contentType_
     * @see etag_
     * @see mtime_
     */
    protected void extractMetadata(HttpHeaders httpHeaders) {
        if (null == httpHeaders) {
            // Nothing to find.
            return;
        }
        contentLength_ = httpHeaders.getContentLength();
        contentMD5_ = httpHeaders.getContentMD5();
        contentType_ = httpHeaders.getContentType();
        etag_ = httpHeaders.getETag();
        mtime_ = httpHeaders.getLastModified();
    }

    /**
     * @param path
     *            the path to set
     */
    public final void setPath(final String path) {
        this.path_ = path;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("MantaObject [path_=").append(path_)
                .append(", contentLength_=").append(contentLength_)
                .append(", contentMD5_=").append(contentMD5_)
                .append(", contentType_=").append(contentType_).append(", etag_=").append(etag_).append(", mtime_=")
                .append(mtime_).append(", dataInputFile_=").append(dataInputFile_).append(", dataInputStream_=")
                .append(dataInputStream_).append(", dataInputString_=").append(dataInputString_)
                .append(", httpHeaders_=").append(httpHeaders_).append("]");

        return builder.toString();
    }

}
