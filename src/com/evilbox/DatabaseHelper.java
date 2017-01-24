package com.evilbox;

import com.evilbox.ResponseAnalyzer.Analyzer;
import com.evilbox.ResponseAnalyzer.ClassifiedSample;
import com.evilbox.Utils.FileUtils;
import com.google.gson.Gson;
import com.kanishka.virustotal.dto.FileScanReport;

import java.io.File;
import java.io.FileWriter;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Mick on 10/09/2016.
 *
 * Questa classe gestisce l'accesso al database e implementa funzionalità
 * per l'accesso e il salvataggio delle risposte di VirusTotal.com
 *
 */
public class DatabaseHelper {

    public static final String DATABASE_FOLDER_PATH = FileUtils.WORKING_DIR + "database"+ File.separator;
    public static final String DATABASE_NAME = "response.db";
    private static final String DATABASE_URL =  "jdbc:sqlite:" + DATABASE_FOLDER_PATH + DATABASE_NAME;
    private static final String DATABASE_JSON_NAME = "evilbox_dataset.json";

    private static final String CREATE_TABLE = "CREATE TABLE IF NOT EXISTS scan_result ( md5_col TEXT PRIMARY KEY NOT NULL," +
            "json_response TEXT, semantic_label TEXT, behaviour TEXT, infection_vector TEXT, goal_primary TEXT, goal_secondary TEXT, asm_path TEXT);";
    private static final String INSERT_RESPONSE = "INSERT INTO scan_result ( md5_col, json_response, semantic_label, behaviour, infection_vector, goal_primary, goal_secondary, asm_path) VALUES ( {values} ); ";
    private static final String QUERY_SCAN_REPORT = "SELECT json_response FROM scan_result WHERE md5_col = '{value}';";
    private static final String CONTAINS_MD5 = "SELECT md5_col FROM scan_result WHERE md5_col = '{value}'";
    private static final String QUERY_ALL_SAMPLES = "SELECT md5_col, semantic_label FROM scan_result";
    private static final String QUERY_ALL_ROWS = "SELECT * FROM scan_result";
    private static final String UPDATE_RESPONSE = "UPDATE scan_result SET  md5_col = '{value}'," +
            " json_response = '{value_2}', semantic_label = '{value_3}', behaviour = '{behaviour}'," +
            " infection_vector = '{vector}', goal_primary = '{goal_primary}',goal_secondary = '{goal_secondary}' WHERE md5_col = '{value}'";
    private static final String COUNT_UNDEF_BEHAVIOUR = "SELECT count(*) FROM scan_result where behaviour = 'undefined'";
    private static final String COUNT_TROJAN = "SELECT count(*) FROM scan_result WHERE behaviour = 'trojan'";
    private static final String COUNT_WORM = "SELECT count(*) FROM scan_result WHERE behaviour = 'worm'";
    private static final String COUNT_VIRUS= "SELECT count(*) FROM scan_result WHERE behaviour = 'virus'";
    private static final String COUNT_BACKDOOR = "SELECT count(*) FROM scan_result WHERE behaviour = 'backdoor'";
    private static final String COUNT_ROOTKIT= "SELECT count(*) FROM scan_result WHERE behaviour = 'rootkit'";
    private static final String COUNT_CLEAN_SAMPLE = "SELECT count(*) FROM scan_result WHERE behaviour = 'not-a-virus'";
    private static final String COUNT_CLASSIFIED_INF_VECT = "SELECT count(*) FROM scan_result WHERE infection_vector  != 'undefined'";
    private static final String COUNT_CLASSIFIED_GOAL_PRIMARY = "SELECT count(*) FROM scan_result WHERE goal_primary  != 'undefined'";
    private static final String COUNT_CLASSIFIED_GOALS_SECONDARY = "SELECT count(*) FROM scan_result WHERE goal_secondary  != 'undefined'";



    /**
     * Creates the SQLite database file
     */
    public static void createDatabase(){

        FileUtils.createDatabaseFolder();

        try {
            Connection connection = DriverManager.getConnection(DATABASE_URL);
            if(connection != null){
                System.out.println("Database Creato"); //todo remove
                Statement statement = connection.createStatement();
                statement.executeUpdate(CREATE_TABLE);
                connection.close();
            }

        }
        catch(Exception exception){
            exception.printStackTrace();

        }
    }

    /**
     * Return a Database connection
     *
     * @return a Connection
     */
    private static Connection getDatabaseConnection(){
        Connection connection = null;
        try{
            connection =  DriverManager.getConnection(DATABASE_URL);
        }
        catch(SQLException exception){
            exception.printStackTrace();
        }
        return connection;
    }

    /**
     * Close an open connection with the Database
     *
     * @param connection connection object to close
     */
    private static void closeDatabaseConnection(Connection connection){
        try{
            connection.close();
        }
        catch(SQLException exception){
            exception.printStackTrace();
        }
    }

    /**
     * Insert an entry into the scan_result database table
     *
     * @param MD5               md5 hash of the analyzed sample
     * @param fileScanReport    report obtained from virustotal.com for the given sample
     * @param label             label obtained from the analysis phase
     * @param fileName          filename of the submitted sample
     */
    public static void insertScanResponse(String MD5, FileScanReport fileScanReport, String label,String fileName){

        String asmFilePath = FileUtils.ASM_FOLDER_RELATIVE_PATH  + FileUtils.changeExtensionToAsm(fileName);
        Gson gson = new Gson();
        String jsonReport = gson.toJson(fileScanReport, FileScanReport.class);
        /*
         * Splitto il label semantico, l'ordinamento sarà sempre behaviour-infection_vector
         * -goal_primario, goal secondario
         */

        ArrayList<String> tokensList = new ArrayList<>(Arrays.asList(label.split("[^0-9a-zA-Z-]")));
        String valorizedQuery = "";
        if(label.equals("not-a-virus")){
            String notVirusValue = "'"+MD5+"', '" + jsonReport + "', '" + label + "'," + "'not-a-virus', 'not-a-virus'," +
                    "'not-a-virus', 'not-a-virus', '" + asmFilePath + "'";
            valorizedQuery = INSERT_RESPONSE.replace("{values}",notVirusValue);
        }
        else {
            String values  = "'"+MD5+"', '" + jsonReport + "', '" + label + "', '" + tokensList.get(0) +"', '"
                    + tokensList.get(1) +"', '" + tokensList.get(2) + "', '" + tokensList.get(3) + "', '"+ asmFilePath + "'";
            valorizedQuery = INSERT_RESPONSE.replace("{values}",values);
        }

        try {
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            statement.executeUpdate(valorizedQuery);
            closeDatabaseConnection(connection);
        }
        catch (SQLException exception){
            exception.printStackTrace();
        }
    }

    /**
     * Update a row in the scan_result table
     *
     * @param MD5               md5 hash of the analyzed sample
     * @param fileScanReport    report obtained from virustotal.com for the given sample
     * @param label             label obtained from the analysis phase
     */
    public static void  updateScanResponse(String MD5, FileScanReport fileScanReport,String label){
        Gson gson = new Gson();
        String jsonReport = gson.toJson(fileScanReport, FileScanReport.class);
        ArrayList<String> tokensList = new ArrayList<>(Arrays.asList(label.split("[^0-9a-zA-Z-]")));

        String valorizedQuery = "";
        if(label.equals("not-a-virus")){
            valorizedQuery = UPDATE_RESPONSE.replace("{value}", MD5)
                                            .replace("{value_2}", jsonReport)
                                            .replace("{value_3}",label)
                                            .replace("{behaviour}","not-a-virus")
                                            .replace("{vector}", "not-a-virus")
                                            .replace("{goal_primary}", "not-a-virus")
                                            .replace("{goal_secondary}", "not-a-virus");
        }
        else {
            valorizedQuery = UPDATE_RESPONSE.replace("{value}", MD5)
                    .replace("{value_2}", jsonReport)
                    .replace("{value_3}",label)
                    .replace("{behaviour}",tokensList.get(0))
                    .replace("{vector}", tokensList.get(1))
                    .replace("{goal_primary}",tokensList.get(2))
                    .replace("{goal_secondary}",tokensList.get(3));

        }
        try {
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();

            statement.executeUpdate(valorizedQuery);
            closeDatabaseConnection(connection);
        }
        catch (SQLException exception){
            exception.printStackTrace();
        }
    }

    /**
     * Return the String representing the .json scan response obtained from VirusTotal.com for
     * the sample identified by MD5 param
     *
     * @param MD5   md5 hash of the sample
     * @return      virustotal.com scanResponse as JSON String if present in database
     */
    public static String getScanResponse(String MD5){
        String scanResponse = null;
        try{
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(QUERY_SCAN_REPORT.replace("{value}", MD5));
            scanResponse = result.getString("json_response");
            closeDatabaseConnection(connection);
        }
        catch(SQLException exception){
            exception.printStackTrace();
        }
        return scanResponse;
    }

    /**
     * Searches the database for the sample identified by MD5 param and returns
     * a FileScanReport Object representing VirusTotal's scan results for the given sample
     *
     * @param MD5   md5 hash to search for
     * @return      FileScanReport Object if the sample is in database
     */
    public static FileScanReport getFileScanReport(String MD5){
        /* return a file scan report instead of a json string */
        Gson gson = new Gson();
        String scanResponse="";
        try{
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(QUERY_SCAN_REPORT.replace("{value}", MD5));
            scanResponse = result.getString("json_response");
            closeDatabaseConnection(connection);
        }
        catch(SQLException exception){
            exception.printStackTrace();
        }

        return gson.fromJson(scanResponse,FileScanReport.class);

    }

    /**
     * Returns true if the sample identified by MD5 param is present in database
     *
     * @param MD5   md5 hash to search for
     * @return      true if present, false otherwise
     */
    public static boolean containsSample(String MD5) {
        try{
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(CONTAINS_MD5.replace("{value}", MD5));
            closeDatabaseConnection(connection);
            /* isBeforeFirst return false if:
             1 there are no results
             2 cursor is not pointing to the position preceding the first

             case 2 will never happen beacause ResultSet has already been initialized
             */

            if(!result.isBeforeFirst()){
                // nessun dato

                return false;
            }
        }
        catch(SQLException exception){
            exception.printStackTrace();
        }

        return true;
    }

    /**
     * Re-runs the scan reports analysis for all entries in database using the built-in
     * analysis engine
     *
     */
    public static void reClassifyAllEntryes(){
        HashMap<String,FileScanReport> temporaryData;
        Gson gson = new Gson();
        try {
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(QUERY_ALL_ROWS);
            temporaryData = new HashMap<>();
            Analyzer analyzer = new Analyzer();
            while (result.next()) {
                String jsonString = result.getString("json_response");
                FileScanReport fileScanReport = gson.fromJson(jsonString,FileScanReport.class);
                temporaryData.put(fileScanReport.getMd5(),fileScanReport);
            }
            closeDatabaseConnection(connection);
            for(String md5 : temporaryData.keySet()){
                FileScanReport fileScanReport = temporaryData.get(md5);
                String freshLabel = analyzer.responseAnalyzerV2(fileScanReport); //todo change with analyzer version of choiche
                DatabaseHelper.updateScanResponse(md5,fileScanReport,freshLabel);

            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Delete the application's database
     *
     * @return  true on success, false otherwise
     */
    public static boolean deleteDatabase() {
        File databasePath = new File(DATABASE_FOLDER_PATH + DATABASE_NAME);
        if (FileUtils.exists(databasePath))
             return databasePath.delete();
        return false;
    }

    /**
     * Generate a .json file containing all entries present in the scan_result table of database.
     * Serialization uses as model the ClassifiedSample class
     * The generated json file is placed in the application's working directory
     *
     */
    public static void generateJSON() {
        ArrayList<ClassifiedSample> dataList = new ArrayList<ClassifiedSample>(100);
        try {
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(QUERY_ALL_SAMPLES);
            while(result.next()){
                ClassifiedSample sample = new ClassifiedSample();
                sample.setMd5(result.getString("md5_col"));
                sample.setLabel(result.getString("semantic_label"));
                dataList.add(sample);

            }
            Gson gson = new Gson();
            FileWriter writer = new FileWriter(FileUtils.WORKING_DIR + DATABASE_JSON_NAME);
            writer.write(gson.toJson(dataList));
            writer.flush();
            writer.close();
            closeDatabaseConnection(connection);
            System.out.println("Database correctly dumped to " + FileUtils.WORKING_DIR);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Generate a evilbox_dataset.json file containing all entries present in the scan_result table of database.
     * Serialization uses as model the ClassifiedSample class
     * The generated json file is placed in the folder identified by target path.
     * If target path is invalid, the file will not be created
     *
     * @param targetPath    path where generated json will be created
     */
    public static void generateJSON(String targetPath) {
        ArrayList<ClassifiedSample> dataList = new ArrayList<ClassifiedSample>(100);
        try {
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(QUERY_ALL_SAMPLES);
            while(result.next()){
                ClassifiedSample sample = new ClassifiedSample();
                sample.setMd5(result.getString("md5_col"));
                sample.setLabel(result.getString("semantic_label"));
                dataList.add(sample);

            }
            Gson gson = new Gson();
            File targetDirectory = new File(targetPath);
            if(!targetDirectory.isDirectory()) {
                System.out.println("ERROR:\tCan't dump database to json file, specify a valid path");
                return;
            }

            FileWriter writer = new FileWriter(targetDirectory + File.separator + DATABASE_JSON_NAME);
            writer.write(gson.toJson(dataList));
            writer.flush();
            writer.close();
            closeDatabaseConnection(connection);
            System.out.println("Database correctly dumped to " + targetDirectory);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Prints statistics about samples in dataset
     * Stats are: total samples, behaviours percentages etc
     */
    public static void printDatasetStats() {
        // please god forgive me for what i did here, time was gone, night was scary, i felt fear

        double totalRows , trojanCount , rootkitCount, backdoorCount, wormCount, virusCount;
        double cleanCount, classInfectVector, classPrimaryGoal, classSecondaryGoal, undefBehaviour;

        try {
            Connection connection = getDatabaseConnection();
            Statement statement = connection.createStatement();

            ResultSet result = statement.executeQuery(COUNT_UNDEF_BEHAVIOUR);
            undefBehaviour = result.getInt(1);

            result = statement.executeQuery(COUNT_TROJAN);
            trojanCount =  result.getInt(1);

            result = statement.executeQuery(COUNT_BACKDOOR);
            backdoorCount = result.getInt(1);

            result = statement.executeQuery(COUNT_ROOTKIT);
            rootkitCount = result.getInt(1);

            result = statement.executeQuery(COUNT_VIRUS);
            virusCount = result.getInt(1);

            result = statement.executeQuery(COUNT_WORM);
            wormCount = result.getInt(1);

            result = statement.executeQuery(COUNT_CLEAN_SAMPLE);
            cleanCount = result.getInt(1);

            result = statement.executeQuery(COUNT_CLASSIFIED_INF_VECT);
            classInfectVector = result.getInt(1);

            result = statement.executeQuery(COUNT_CLASSIFIED_GOAL_PRIMARY);
            classPrimaryGoal = result.getInt(1);

            result = statement.executeQuery(COUNT_CLASSIFIED_GOALS_SECONDARY);
            classSecondaryGoal = result.getInt(1);

            totalRows = trojanCount + backdoorCount + wormCount + virusCount+rootkitCount+cleanCount+undefBehaviour;

            double maliciousSamples = totalRows - cleanCount - undefBehaviour;
            double trojPercentage = (trojanCount / maliciousSamples) * 100;
            double backPercentage = (backdoorCount / maliciousSamples) * 100;
            double rootPercentage = (rootkitCount / maliciousSamples) * 100;
            double wormPercentage = (wormCount / maliciousSamples) * 100;
            double virusPercentage = (virusCount / maliciousSamples) * 100;
            double detectedInfVectPer = ((classInfectVector - cleanCount) / maliciousSamples) * 100;
            double detectedPrimGoalPer = ((classPrimaryGoal - cleanCount) / maliciousSamples) * 100;
            double detectedSecGoalPer = ((classSecondaryGoal - cleanCount) / maliciousSamples) * 100;

            System.out.println("##############################  Dataset Statistics ##############################");
            System.out.printf("\n\t%-50s %15.0f%n","Total samples:",  totalRows);
            System.out.format("\t%-50s %15.0f%n","Clean samples:", cleanCount);
            System.out.format("\t%-50s %15.0f%n","Unclassified samples:", undefBehaviour);
            System.out.format("\n\t%-50s %15.0f%n%n","Malicious samples:", maliciousSamples);
            System.out.format("\t%-50s %15.2f%s (%.0f)%n","Trojan:", trojPercentage, "%", trojanCount);
            System.out.format("\t%-50s %15.2f%s (%.0f)%n","Backdoor:", backPercentage, "%", backdoorCount);
            System.out.format("\t%-50s %15.2f%s (%.0f)%n","Rootkit:", rootPercentage, "%", rootkitCount); 
            System.out.format("\t%-50s %15.2f%s (%.0f)%n","Worm:", wormPercentage, "%", wormCount);
            System.out.format("\t%-50s %15.2f%s (%.0f)%n","Virus:", virusPercentage, "%", virusCount);
            System.out.format("\n\t%-50s %15.2f%s%n", "Classified Infection Vector:", detectedInfVectPer, "%");
            System.out.format("\t%-50s %15.2f%s%n","Classified Primary Goals:", detectedPrimGoalPer, "%");
            System.out.format("\t%-50s %15.2f%s%n","Classified Secondary Goals:" ,detectedSecGoalPer, "%");
            System.out.println("\n#################################################################################");


        }
        catch (Exception e) {
            e.printStackTrace();
        }


    }


    /**
     * Saves a FileScanReport Object to a .json file in the application's working directory.
     * The MD5 param will be used as filename.
     *
     * @param report    FileScanReport Object to save
     * @param md5       md5 hash of the file associated with the FileScanReport Object
     */
    public static void saveResponseToFile(FileScanReport report,String md5) {
        Gson gson = new Gson();
        try {
            FileWriter writer = new FileWriter(FileUtils.WORKING_DIR + md5 +".json");
            writer.write(gson.toJson(report));
            writer.flush();
            writer.close();

        }catch(Exception e ){
            e.printStackTrace();
        }
    }

    }
