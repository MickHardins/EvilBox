package com.evilbox.Request;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

import com.evilbox.DatabaseHelper;
import com.evilbox.ResponseAnalyzer.Analyzer;
import com.evilbox.Utils.FileUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;


/**
 * Created by Mick on 30/08/2016.
 *
 * This class send request to VirusTotal.com and wait for responses.
 *
 */
public class RequestSender {

    private static final int HTTP_TIME_DELAY = 15000 + 1000; // 15s + 1s tolerance
    private HashMap<String,String> notReadyScans; // key = md5, value = filename
    private boolean forceReAnalysis;
    private VirustotalPublicV2 virustotalPublicV2;
    private final String WAITING_MESSAGE = "Waiting to stay within HTTP request limit\n";
    private String zipPassword;



    /**
     * Default constructor
     *
     */
    public RequestSender(){
        this.notReadyScans = new HashMap<>();
        forceReAnalysis = false;
        initialize();
    }

    /**
     * Constructor for RequestSender Object.
     * If forceReAnalysis param is true, a request will be sent to virustptal.com even if a given sample
     * is already in application's database
     *
     * @param forceReAnalysis   true if we want another report from virustotal
     */
    public RequestSender(boolean forceReAnalysis){
        this.notReadyScans = new HashMap<>();
        this.forceReAnalysis = forceReAnalysis;
        initialize();
    }


    public void initialize() {
        // Read API Key
        String apiKey = FileUtils.getVirusTotalApiKey();
        if (apiKey.equalsIgnoreCase(FileUtils.DEFAULT_API_KEY)) {
            System.out.println("ERROR:\tYou must set a valid API key. Terminating...");
            System.exit(1);
        }
        VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKey);
        try {
            virustotalPublicV2 = new VirustotalPublicV2Impl();
        }
        catch (APIKeyNotFoundException e) {
            e.printStackTrace();
            System.out.println("ERROR:\tApi key not found");
        }
    }

    /**
     * Send a request for each file present in folderPath directory,
     * if zip files are present, they'll be unzipped, and the inner file will be sent
     * In order to work a valid path must be supplied.
     * Since a public version of virustotal API is in use,
     * the request sender waits 16 seconds between two request.
     *
     * For more infos: https://www.virustotal.com/it/documentation/public-api/
     *
     * @param folderPath    path of the folder with samples to analyze
     */
    public void postFileList(String folderPath) {  //run diorectopry analysis

        Analyzer analyzer = new Analyzer(); //todo version
        File[] samplesList;
        if (folderPath == null) {
            //use default path
            samplesList = FileUtils.getSampleFileList();
            System.out.println("Analyzing samples in folder "+ FileUtils.SAMPLES_FOLDER_PATH);
        }
        else {
            samplesList = FileUtils.getSampleFileList(folderPath); // Sample.fromFolder(folderPath);
            System.out.println("Analyzing samples in folder "+ folderPath);
        }

        if (samplesList.length == 0) {
            System.out.println("ERROR:\t No files to analyze in folder" + folderPath);
            return;
        }

        // SampleUnzipper unzipper = new SampleUnzipper(samplesList);

        for (File sample : samplesList) {
            String fileExtension = FileUtils.getFileExtension(sample.getName()); // sample.getExtension()
            File fileToSend;

            if (fileExtension.equals(".zip")) { // sample.isZip();
                String innerFileName = FileUtils.unzipToSamplesSubdir(sample); // sample.unzipToSubdirectory(...);
                String innerFilePath = FileUtils.UNZIPPED_SAMPLES_PATH + innerFileName;
                fileToSend = new File(innerFilePath);
            }
            else {
                fileToSend = sample;
            }

            if (!FileUtils.exists(fileToSend))
                continue;

            String md5 = FileUtils.calculateMD5(fileToSend);
            boolean isInDatabase = DatabaseHelper.containsSample(md5);

            if (!isInDatabase) {
                // send and do analysis
                // first we try with md5, if we are lucky virus total already has the file
                FileScanReport fileScanReport = postRequestMD5(md5, fileToSend.getName());
                if (fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    //scan is queued we try later
                    continue;
                }
                if (fileScanReport.getResponseCode() != 1) {
                    //we must send the file
                    fileScanReport = postFileRequest(fileToSend);
                }
                // our label
                String sampleLabel = analyzer.responseAnalyzerV2(fileScanReport);
                // Insert into database
                DatabaseHelper.insertScanResponse(md5,fileScanReport,sampleLabel,fileToSend.getName());

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }
            else if (isInDatabase && forceReAnalysis) {
                FileScanReport fileScanReport = postRequestMD5(md5, fileToSend.getName());
                if ( fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    // scan is queued we try later
                    continue;
                }
                if (fileScanReport.getResponseCode() != 1) {
                    // we must send the file
                    fileScanReport = postFileRequest(fileToSend);
                }
                // our label
                String sampleLabel = analyzer.responseAnalyzerV2(fileScanReport);
                // insert into database
                DatabaseHelper.updateScanResponse(md5,fileScanReport,sampleLabel);

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }

            }
            else {
                // skip this file
                continue;
            }

        }
        retrieveQueuedReport();

    }

    /**
     * Send a request for each file present in folderPath directory,
     * if zip files are present, they'll be unzipped using the supplied password,
     * and the inner file will be sent.
     * In order to work a valid path must be supplied.
     *
     * Since a public version of virustotal API is in use,
     * the request sender waits 16 seconds between two request.
     *
     * For more infos: https://www.virustotal.com/it/documentation/public-api/
     *
     * @param folderPath    path of the folder with samples to analyze
     * @param zipPassword   password to unzip .zip files
     */
    public void postFileList(String folderPath, String zipPassword) {  //run diorectopry analysis

        Analyzer analyzer = new Analyzer(); //todo version
        File[] samplesList;
        String pathToPrint;
        if (folderPath == null) {
            //use default path
            samplesList = FileUtils.getSampleFileList();
            pathToPrint = FileUtils.SAMPLES_FOLDER_PATH;
            System.out.println("Analyzing samples in folder "+ pathToPrint);
        }
        else {
            samplesList = FileUtils.getSampleFileList(folderPath);
            pathToPrint = folderPath;
            System.out.println("Analyzing samples in folder "+ folderPath);
        }

        if (samplesList.length == 0) {
            System.out.println("ERROR:\t No files to analyze in folder" + pathToPrint);
            return;
        }


        for (File sample : samplesList) {
            String fileExtension = FileUtils.getFileExtension(sample.getName());
            File fileToSend;

            if (fileExtension.equals(".zip")) {
                String innerFileName = FileUtils.unzipToSamplesSubdir(sample,zipPassword);
                String innerFilePath = FileUtils.UNZIPPED_SAMPLES_PATH + innerFileName;
                fileToSend = new File(innerFilePath);
            }
            else {
                fileToSend = sample;
            }

            if (!FileUtils.exists(fileToSend))
                continue;

            String md5 = FileUtils.calculateMD5(fileToSend);
            boolean isInDatabase = DatabaseHelper.containsSample(md5);

            if (!isInDatabase) {
                //send and do analysis
                // first we try with md5, if we are lucky virus total already has the file
                FileScanReport fileScanReport = postRequestMD5(md5, fileToSend.getName());
                if (fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    //scan is queued we try later
                    continue;
                }
                if (fileScanReport.getResponseCode() != 1) {
                    //we must send the file
                    fileScanReport = postFileRequest(fileToSend);
                }
                // our label
                String sampleLabel = analyzer.responseAnalyzerV2(fileScanReport);
                // Insert into database
                DatabaseHelper.insertScanResponse(md5,fileScanReport,sampleLabel,fileToSend.getName());

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }
            }
            else if (isInDatabase && forceReAnalysis) {
                FileScanReport fileScanReport = postRequestMD5(md5, fileToSend.getName());
                if ( fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    //scan is queued we try later
                    continue;
                }
                if (fileScanReport.getResponseCode() != 1) {
                    //we must send the file
                    fileScanReport = postFileRequest(fileToSend);
                }
                // our label
                String sampleLabel = analyzer.responseAnalyzerV2(fileScanReport);
                // Insert into database
                DatabaseHelper.updateScanResponse(md5,fileScanReport,sampleLabel);

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }

            }
            else {
                //skip this file
                continue;
            }

        }
        retrieveQueuedReport();
    }

    /**
     * Sends a request using MD5 as resource, and waits for VirusTotal response.
     * If the resource is still in queue and a report can't be retrieved,
     * the information is saved to notReadyScans HashMap to try again later.
     *
     * notReadyScans has key = MD5   value = filename
     *
     * @param md5String     md5 hash to send
     * @param fileName      name of sample
     * @return              a FileScanReport object with samples infos
     */
    public FileScanReport postRequestMD5(String md5String, String fileName){

        FileScanReport scanReport = null;

        String response = null;
        try {
            System.out.println("Waiting for virustotal response...");
            scanReport = virustotalPublicV2.getScanReport(md5String);
            System.out.println("Response arrived: saving "+md5String+" to database\n");

        }
        catch (Exception exception) {
            exception.printStackTrace();
        }
        if (scanReport == null || scanReport.getResponseCode() == 2) {
            notReadyScans.put(md5String, fileName);
        }
        return scanReport;
    }

    // invia il sample da analizzare a virustotal.com e

    /**
     * Send a File to VirusTotal and waits for response, on success, it reads
     * the resource identificator sent by VT and perform another MD5 request
     * to obtain a FileScanReportObject.
     *
     * @param file  file to send to VirusTotal.com
     * @return      FileScanReport Object containing sample's informations
     */
    public FileScanReport postFileRequest(File file){

        FileScanReport fileScanReport= null;
        try {
            if ((file.length()/(1024*1024)) > 32) { //size in MB
                System.out.println(file.getName() + " is bigger than 32MB can't send it to virustotal");
                return null;
            }

            System.out.println("Waiting for Virustotal file response...");
            ScanInfo scanInfo = virustotalPublicV2.scanFile(file); // scan info contains the results
            System.out.println("Response has arrived, requesting scan result with the received MD5...");
            String fileMD5 = scanInfo.getMd5();
            fileScanReport = postRequestMD5(fileMD5, file.getName());
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        return fileScanReport;
    }

    /**
     * Performs a series of MD5 request to VirusTotal.com.
     * The MD5 list is obtained by parsing all json files in the folder specified by
     * the param.
     *
     * Since a public version of virustotal API is in use,
     * the request sender waits 16 seconds between two request.
     *
     * @param scrapedJsonPath   folder to search json files
     */
    public void postMD5ListRequest(String scrapedJsonPath) {
        ArrayList<String> md5List;
        String pathToPrint;
        if(scrapedJsonPath == null) {
            md5List = FileUtils.parseScrapedJSON();
            pathToPrint = FileUtils.SCRAPED_JSON_PATH;
            System.out.println("Analyzing MD5 list parsed from .json files in folder "+pathToPrint);
        }
        else {
            md5List = FileUtils.parseScrapedJSON(scrapedJsonPath);
            pathToPrint = scrapedJsonPath;
            System.out.println("Analyzing MD5 list parsed from .json files in folder "+pathToPrint);
        }
        if (md5List.size() <=0) {
            System.err.println("ERROR:\t No json to analyze in folder " + pathToPrint); //todo cambiare il tipo di errore se c'è stato un problema nel parsing json
            return;
        }
        Analyzer analyzer = new Analyzer();
        for (String md5 : md5List) {
            boolean isInDatabase = DatabaseHelper.containsSample(md5);
            /*
             * TODO Rimuovere il check su `isInDatabase` dal corpo principale ed
             * utilizzarlo solo per differenziare la chiamata update vs insert
             */
            boolean shouldAnalyze = !isInDatabase || (isInDatabase && forceReAnalysis);
            if (!isInDatabase) {
                //send and do analysis

                String filename = FileUtils.FILE_NOT_AVAILABLE;
                FileScanReport fileScanReport = postRequestMD5(md5,filename);
                if ( fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    //scan is queued we try later
                    continue;
                }

                // our label
                String sampleLabel = analyzer.responseAnalyzer(fileScanReport);


                // Insert into database
                DatabaseHelper.insertScanResponse(md5, fileScanReport, sampleLabel,filename);

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }
            }
            else if (isInDatabase && forceReAnalysis) {
                String filename = FileUtils.FILE_NOT_AVAILABLE;
                FileScanReport fileScanReport = postRequestMD5(md5,filename);
                if (fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    // scan is queued we try later
                    continue;
                }

                // our label
                String sampleLabel = analyzer.responseAnalyzer(fileScanReport);


                // Insert into database
                DatabaseHelper.updateScanResponse(md5, fileScanReport, sampleLabel);

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }
            }
            else {
                //skip this md5
                continue;
            }
        }


    }

    /**
     * Try to retrieve queued scanReport.
     *
     *
     */
    public void retrieveQueuedReport() {
        if (notReadyScans == null || notReadyScans.size() == 0)
            return;
        Analyzer analyzer = new Analyzer();
        System.out.println("Some files were queued for analysis at VirusTotal.com - Checking if scan report are available");
        for(String md5 : notReadyScans.keySet()) {
            String filename = notReadyScans.get(md5);
            boolean isInDatabase = DatabaseHelper.containsSample(md5);
            if (!isInDatabase) { //TODO il punto interrgoativo!! & check per forzare il reinserimento
                //send and do analysis


                FileScanReport fileScanReport = postRequestMD5(md5,filename);
                if ( fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    //scan is queued we try later
                    continue;
                }

                // our label
                String sampleLabel = analyzer.responseAnalyzer(fileScanReport);


                // Insert into database
                DatabaseHelper.insertScanResponse(md5, fileScanReport, sampleLabel,filename);

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }
            }
            else if (isInDatabase && forceReAnalysis) {

                FileScanReport fileScanReport = postRequestMD5(md5,filename);
                if ( fileScanReport == null || fileScanReport.getResponseCode() == 2) {
                    //scan is queued we try later
                    continue;
                }

                // our label
                String sampleLabel = analyzer.responseAnalyzer(fileScanReport);


                // Insert into database
                DatabaseHelper.updateScanResponse(md5, fileScanReport, sampleLabel);

                try {
                    System.out.println(WAITING_MESSAGE);
                    Thread.sleep(HTTP_TIME_DELAY);
                }
                catch (Exception e ) {
                    e.printStackTrace();
                }
            }
            else {
                //skip this md5
                continue;
            }
        }

    }

    /**
     * Prints the list of files sent to virustotal, but still queued for analysis
     */
    public void reportQueuedFiles() {
        if (notReadyScans == null || notReadyScans.size() == 0) {
            return;
        }
        System.out.println("############### File still in queue for scan ###############\n");
        for(String md5 : notReadyScans.keySet()) {
            System.out.println("File with MD5 = "+ md5 +" queued for scan, try later for results");
        }
    }

    /*public FileScanReport postScanIdRequest(String scanId) {
        // can be retrieved using the same method
        return this.postRequestMD5(scanId);
    }*/



    
}
