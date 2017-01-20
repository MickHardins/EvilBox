package com.evilbox.Utils;

/**
 * Created by mick on 10/01/17.
 *
 * This class represent the directory structure of application.
 * This class is serialized to json to create evilbox_cfg.json
 *
 */
public class DirectoryStructure {



    private String samplesFolderPath;
    private String unzippedSamplePath;
    private String databaseFolderPath;
    private String asmFolderPath;
    private String idaProPath;
    private String virusTotalApiKey;

    public String getVirusTotalApiKey() {
        return virusTotalApiKey;
    }

    public void setVirusTotalApiKey(String virusTotalApiKey) {
        this.virusTotalApiKey = virusTotalApiKey;
    }

    public String getSamplesFolderPath() {
        return samplesFolderPath;
    }

    public void setSamplesFolderPath(String samplesFolderPath) {
        this.samplesFolderPath = samplesFolderPath;
    }

    public String getUnzippedSamplePath() {
        return unzippedSamplePath;
    }

    public void setUnzippedSamplePath(String unzippedSamplePath) {
        this.unzippedSamplePath = unzippedSamplePath;
    }

    public String getDatabaseFolderPath() {
        return databaseFolderPath;
    }

    public void setDatabaseFolderPath(String databaseFolderPath) {
        this.databaseFolderPath = databaseFolderPath;
    }

    public String getAsmFolderPath() {
        return asmFolderPath;
    }

    public void setAsmFolderPath(String asmFolderPath) {
        this.asmFolderPath = asmFolderPath;
    }

    public String getIdaProPath() {
        return idaProPath;
    }

    public void setIdaProPath(String idaProPath) {
        this.idaProPath = idaProPath;
    }


}
