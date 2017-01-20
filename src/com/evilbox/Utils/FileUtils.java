package com.evilbox.Utils;

import com.evilbox.DatabaseHelper;
import com.evilbox.ScrapedSamplesInfos;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.FileHeader;

import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.StringJoiner;

/**
 * Contains useful methods to interact with filesystem and files.
 * Generates the directory structure of the applications and manages it's files
 */
public class FileUtils {

    public static String WORKING_DIR = System.getProperty("user.dir") + File.separator;
    public static String SAMPLES_FOLDER_PATH = WORKING_DIR +"samples"+ File.separator;
    public static String UNZIPPED_SAMPLES_PATH = SAMPLES_FOLDER_PATH + "unzipped" +File.separator;
    public static String ASM_FOLDER_ABS_PATH = WORKING_DIR + "asm_files"+File.separator;
    public static String ASM_FOLDER_RELATIVE_PATH = File.separator + "asm_files"+ File.separator;
    public static String SCRAPED_JSON_PATH = WORKING_DIR + "scraped_json" + File.separator;
    public static String EVILBOX_CONFIG_JSON_NAME = "evilbox_cfg.json";
    public static String FILE_NOT_AVAILABLE = "File not available, scanReport retrieved by MD5 scraping";
    public static String DEFAULT_API_KEY = "Insert VirusTotal API key";
    public static String DEFAULT_IDA_PRO_PATH ="Insert path to idaw or idal executables";
    private static String[] defaultPSW = { "infected", "malware", "virus"};


    /**
     * this method creates the directory structure for the applications
     * If not present, also the database file will be created
     */
    public static void createDirectoryStructure() {
        createFolder(SAMPLES_FOLDER_PATH);
        createFolder(UNZIPPED_SAMPLES_PATH);
        createFolder(ASM_FOLDER_ABS_PATH);
        createFolder(SCRAPED_JSON_PATH);
        createFolder(DatabaseHelper.DATABASE_FOLDER_PATH);
        generateConfigJSON();
        File db = new File(DatabaseHelper.DATABASE_FOLDER_PATH + DatabaseHelper.DATABASE_NAME);
        if(!FileUtils.exists(db))
            DatabaseHelper.createDatabase();
    }

    /**
     *  If not present, creates the folder to contains samples
     */
    private static void createSampleFolder() {

        File projectDir = new File(SAMPLES_FOLDER_PATH);
        if (!projectDir.exists())
            projectDir.mkdirs();

    }

    /**
     * Creates a new folder, if not already present
     * @param path the path where the folder will be created
     */
    private static void createFolder(String path) {
        File directory = new File(path);
        if( !directory.exists())
            directory.mkdirs();
    }

    /**
     *  If not present, creates the folder to contain teh database
     */
    public static void  createDatabaseFolder() {
        File databaseFolder = new File(DatabaseHelper.DATABASE_FOLDER_PATH);
        if( !databaseFolder.exists())
            databaseFolder.mkdirs();
    }

    /**
     * Test wether a file exists or not
     * @param f the file Object
     * @return true if the file exists, false otherwise
     */
    public static boolean exists(File f) {
        return (f.exists() && !f.isDirectory());
    }

    public static File[] getFileList(String path){
        File sampleFolder = new File(path);
        return sampleFolder.listFiles();
    }

    /**
     * Unzip a file to the /sample/unzipped directory
     * @param file file to unzip
     * @return extracted fileName as String
     */
    public static String unzipToSamplesSubdir(File file) {
        String extractedFileName = "";
        for (String psw : defaultPSW) {
            try {

                ZipFile zipFile = new ZipFile(file);
                if(zipFile.isEncrypted()) {
                    zipFile.setPassword(psw);
                }
                ArrayList fileHeaderList = (ArrayList)zipFile.getFileHeaders();
                for (int i = 0; i< fileHeaderList.size();i++) {
                    FileHeader fileHeader = (FileHeader)fileHeaderList.get(i);
                    extractedFileName = fileHeader.getFileName();
                }

                zipFile.extractAll(UNZIPPED_SAMPLES_PATH); //estrae cmq un file anche se sbaglia la password
                return extractedFileName;
            } catch (ZipException e) {
                //e.printStackTrace();
                System.out.println("Unzip failed, trying another password");
                File f = new File(UNZIPPED_SAMPLES_PATH + extractedFileName);
                if (FileUtils.exists(f))
                    f.delete();
            }

        }
        return extractedFileName;
    }

    /**
     *
     * @param file file to unzip
     * @param suppliedPassword password of the file to unzip
     * @return extracted fileName as String
     */
    public static String unzipToSamplesSubdir(File file, String suppliedPassword) {
        String extractedFileName = "";
        try {
            ZipFile zipFile = new ZipFile(file);
            if(zipFile.isEncrypted()) {
                zipFile.setPassword(suppliedPassword);
            }
            ArrayList fileHeaderList = (ArrayList)zipFile.getFileHeaders();
            for(int i = 0; i< fileHeaderList.size();i++){
                FileHeader fileHeader = (FileHeader)fileHeaderList.get(i);
                extractedFileName = fileHeader.getFileName();
            }

            zipFile.extractAll(UNZIPPED_SAMPLES_PATH);

        } catch (Exception e){
            //e.printStackTrace();
            System.err.println("ERROR:\tUnzip for file " + file + " failed with supplied password");
            File f = new File(UNZIPPED_SAMPLES_PATH + extractedFileName);
            if (FileUtils.exists(f))
                f.delete();
        }
        return extractedFileName;
    }

    /**
     * This method searches for .json files in the directory specified by the scrapedJsonPath param,
     * then returns an ArrayList of MD5 parsed from them.
     * @param scrapedJsonPath path where .json files are located
     * @return list of MD5 parsed from .json files
     */
    public static ArrayList<String> parseScrapedJSON(String scrapedJsonPath) {
        File[] files;
        ArrayList<String> result = new ArrayList<>();

        files = FileUtils.getSampleFileList(scrapedJsonPath,".json");

        Gson gson = new Gson();
        for(File file: files){
            ScrapedSamplesInfos[] sampleList = {};
            try{
                JsonReader reader = new JsonReader(new FileReader(file));
                sampleList = gson.fromJson(reader,ScrapedSamplesInfos[].class);

            }
            catch(Exception e){
                e.printStackTrace();
            }
            if(sampleList.length == 0){
                continue;
            }
            for (ScrapedSamplesInfos sample : sampleList) {
                result.add(sample.getMd5());
            }
        }
        return result;
    }

    /**
     * This method searches for .json files in the default directory: /scraped_json,
     * then returns an ArrayList of MD5 parsed from them.
     * @return list of MD5 parsed from .json files
     */
    public static ArrayList<String> parseScrapedJSON() {
        File[] files;
        ArrayList<String> result = new ArrayList<>();

        files = FileUtils.getSampleFileList(FileUtils.SCRAPED_JSON_PATH,".json");

        Gson gson = new Gson();
        for(File file: files){
            ScrapedSamplesInfos[] sampleList = {};
            try{
                JsonReader reader = new JsonReader(new FileReader(file));
                sampleList = gson.fromJson(reader,ScrapedSamplesInfos[].class);

            }
            catch(Exception e){
                e.printStackTrace();
            }
            if(sampleList.length == 0){
                continue;
            }
            for (ScrapedSamplesInfos sample : sampleList) {
                result.add(sample.getMd5());
            }
        }
        return result;
    }

    /**
     * This methods delete all files from the /samples/unzipped directory
     */
    public static void deleteAllUnzippedFiles() {
        File[] fileList = getSampleFileList(FileUtils.UNZIPPED_SAMPLES_PATH );
        if(fileList.length == 0) {
            System.out.println("No unzipped files to delete");
            return;
        }

        for( File file : fileList) {
            file.delete();
            System.out.println(file + " has been deleted");
        }
        System.out.println("Cleaning of unzipped file complete");

    }

    /**
     *  Returns a list of files present in the default samples directory,
     *  hidden files are ignored.
     *
     *  @return list of file present in /samples directory
     */
    public static File[] getSampleFileList() {
        createSampleFolder();
        File sampleFolder = new File(SAMPLES_FOLDER_PATH);
        File[] result = sampleFolder.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                String filename = pathname.getName().toLowerCase();
                return (!filename.startsWith(".") && !pathname.isHidden() && !pathname.isDirectory());
            }
        });
        return result;
    }

    /**
     *  Returns a list of files present in the directory denoted by folderPath param,
     *  hidden files are ignored.
     *
     * @param folderPath path of the target folder
     * @return list of files in the target folder
     */
    public static File[] getSampleFileList(String folderPath) {

        File sampleFolder = new File(folderPath);
        if(!sampleFolder.isDirectory())
            return new File[]{};
        File[] result = sampleFolder.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                String filename = pathname.getName().toLowerCase();
                return (!filename.startsWith(".") && !pathname.isHidden() && !pathname.isDirectory());
            }
        });
        return result;
    }

    /**
     *  Returns a list of files present in the directory denoted by folderPath param filtered by
     *  supplied extension, hidden files are ignored.
     *
     * @param folderPath path of the target folder
     * @param fileExtension extension of the files to list
     * @return list of files in the target folder with supplied extensions
     */
    public static File[] getSampleFileList(String folderPath, String fileExtension) {

        File sampleFolder = new File(folderPath);
        if(!sampleFolder.isDirectory())
            return new File[]{};
        File[] result = sampleFolder.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                String filename = pathname.getName().toLowerCase();
                String extension = FileUtils.getFileExtension(filename);
                boolean match = extension.equalsIgnoreCase(fileExtension);
                return (!filename.startsWith(".") && match && !pathname.isHidden() && !pathname.isDirectory());
            }
        });
        return result;
    }

    /**
     * Return the file extensions for the given filename.
     *
     * @param fileName name of file
     * @return file extensions
     */
    public static String getFileExtension(String fileName) {

        String extension="";
        int start = fileName.lastIndexOf(".");
        if(start != -1){
            extension = fileName.substring(start, fileName.length());
        }
        return extension;

    }

    /**
     * Change filename extensions to .asm
     * Example: filename.zip --> filename.asm
     *
     * @param filename name of file that will be changed
     * @return modified file name with .asm extension
     */
    public static String changeExtensionToAsm(String filename) {
        String result = "";
        int end = filename.lastIndexOf('.');
        if(end == -1) {
            return filename + ".asm";
        }
        else {
            result = filename.substring(0,end) + ".asm";
        }
        return result;
    }

    /**
     * Return the MD5 hash of a given file as String.
     *
     * @param file input File object
     * @return md5 hash for the given file
     */
    public static String calculateMD5(File file){
        String md5Hash ="";
        try {
            FileInputStream fileInputStream = new FileInputStream(file);

            MessageDigest md = MessageDigest.getInstance("MD5");
            DigestInputStream dis = new DigestInputStream(fileInputStream, md);
            byte[] buffer = new byte[1024];
            int read = dis.read(buffer);
            while (read > -1) {
                read = dis.read(buffer);
            }
            byte[] md5Array = dis.getMessageDigest().digest();

            BigInteger bigInt = new BigInteger(1,md5Array);
            md5Hash = bigInt.toString(16);
            // Now we need to zero pad it if you actually want the full 32 chars.
            while(md5Hash.length() < 32 ){
                md5Hash = "0"+md5Hash;
            }

            //md5Hash = Arrays.toString(dis.getMessageDigest().digest());
            fileInputStream.close();
        }
        catch(Exception ex){
            ex.printStackTrace();
        }
        return md5Hash;
    }

    /**
     * Generate evilbox_cfg.json file in the working directory.
     * evilbox_cfg.json will contain the directory srtucture of the application, its structure it's the following:
     *      {
     *          "SAMPLES_FOLDER_PATH": path to the samples' folder,
     *          "UNZIPPED_SAMPLE_PATH": path to unzipped samples,
     *          "DATABASE_FOLDER_PATH": path to database,
     *          "ASM_FOLDER_PATH": path to generated asm folder,
     *          "IDA_PRO_PATH": "path to idaw or idal executables"
     *       }
     *
     */
    public static void generateConfigJSON() {
        File configFile = new File(WORKING_DIR + EVILBOX_CONFIG_JSON_NAME);
        if(exists(configFile)) {
            return;
        }

        DirectoryStructure ds = new DirectoryStructure();
        ds.setAsmFolderPath(ASM_FOLDER_ABS_PATH);
        ds.setDatabaseFolderPath(DatabaseHelper.DATABASE_FOLDER_PATH);
        ds.setSamplesFolderPath(SAMPLES_FOLDER_PATH);
        ds.setUnzippedSamplePath(UNZIPPED_SAMPLES_PATH);
        ds.setIdaProPath(DEFAULT_IDA_PRO_PATH);
        ds.setVirusTotalApiKey(DEFAULT_API_KEY);
        Gson gson = new Gson();

        try {
            FileWriter writer = new FileWriter(WORKING_DIR +  EVILBOX_CONFIG_JSON_NAME );
            writer.write(gson.toJson(ds));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(EVILBOX_CONFIG_JSON_NAME + " correctly created in folder: " + FileUtils.WORKING_DIR);
    }

    /**
     * Generate evilbox_cfg.json file in the target path
     * evilbox_cfg.json will contain the directory srtucture of the application, its structure it's the following:
     *      {
     *          "SAMPLES_FOLDER_PATH": path to the samples' folder,
     *          "UNZIPPED_SAMPLE_PATH": path to unzipped samples,
     *          "DATABASE_FOLDER_PATH": path to database,
     *          "ASM_FOLDER_PATH": path to generated asm folder,
     *          "IDA_PRO_PATH": "path to idaw or idal executables"
     *       }
     *
     * @param targetPath path where evilbox_cfg.json will be created
     */
    public static void generateConfigJSON(String targetPath) {
        File configFile = new File(targetPath + EVILBOX_CONFIG_JSON_NAME);
        if(exists(configFile)) {
            return;
        }
        DirectoryStructure ds = new DirectoryStructure();
        ds.setAsmFolderPath(ASM_FOLDER_ABS_PATH);
        ds.setDatabaseFolderPath(DatabaseHelper.DATABASE_FOLDER_PATH);
        ds.setSamplesFolderPath(SAMPLES_FOLDER_PATH);
        ds.setUnzippedSamplePath(UNZIPPED_SAMPLES_PATH);
        ds.setIdaProPath(DEFAULT_IDA_PRO_PATH);
        ds.setVirusTotalApiKey(DEFAULT_API_KEY);
        Gson gson = new Gson();
        File targetFolder = new File(targetPath);
        if (!targetFolder.isDirectory()) {
            System.err.println("ERROR:\tCan't generate "+ EVILBOX_CONFIG_JSON_NAME +", did you specify a valid folder?");
            return;
        }
        try {
            FileWriter writer = new FileWriter(targetFolder + File.separator + EVILBOX_CONFIG_JSON_NAME);
            writer.write(gson.toJson(ds));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(EVILBOX_CONFIG_JSON_NAME + " correctly created in folder: " + targetPath);
    }

    /**
     * Parsa il file evilbox_cfg.json
     * @return  a DirectoryStructure object
     */
    public static DirectoryStructure parseEvilBoxConfigJSON() {
        Gson gson = new Gson();
        File cfgJSON = new File(FileUtils.WORKING_DIR + EVILBOX_CONFIG_JSON_NAME);
        DirectoryStructure ds = null;
        try {
            JsonReader jsonReader = new JsonReader(new FileReader(cfgJSON));
            ds = gson.fromJson(jsonReader,DirectoryStructure.class);
        }
        catch (FileNotFoundException exception) {
            System.out.println("Can't find " + EVILBOX_CONFIG_JSON_NAME + " file");
        }
        return ds;

    }

    public static String getVirusTotalApiKey() {
        DirectoryStructure ds = FileUtils.parseEvilBoxConfigJSON();
        return ds.getVirusTotalApiKey();
    }
}
