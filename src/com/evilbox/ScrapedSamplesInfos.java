package com.evilbox;

import com.google.gson.annotations.SerializedName;

/**
 * Created by Mick on 20/11/2016.
 */
public class ScrapedSamplesInfos {

    @SerializedName("md5")
    String md5;
    @SerializedName("original_filename")
    String originalFilename;
    @SerializedName("type")
    String type;

    public ScrapedSamplesInfos(){

    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getOriginalFilename() {
        return originalFilename;
    }

    public void setOriginalFilename(String originalFilename) {
        this.originalFilename = originalFilename;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
