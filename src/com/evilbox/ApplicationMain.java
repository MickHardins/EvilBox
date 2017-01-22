package com.evilbox;

import com.evilbox.Request.RequestSender;
import com.evilbox.Utils.ArgumentOptions;
import com.evilbox.Utils.FileUtils;
import org.apache.commons.cli.*;

import java.util.Scanner;


/**
 * Created by mrest on 30/08/2016.
 */
public class ApplicationMain {

    private final static String appHeader = "\n"
            + "    8888888888         d8b 888      888888b.\n"
            + "    888                Y8P 888      888  \"88b\n"
            + "    888                    888      888  .88P\n"
            + "    8888888   888  888 888 888      8888888K.   .d88b.  888  888\n"
            + "    888       888  888 888 888      888  \"Y88b d88\"\"88b `Y8bd8P'\n"
            + "    888       Y88  88P 888 888      888    888 888  888   X88K\n"
            + "    888        Y8bd8P  888 888      888   d88P Y88..88P .d8\"\"8b.\n"
            + "    8888888888  Y88P   888 888      8888888P\"   \"Y88P\"  888  888\n\n\n";

    private final static String appFooter = "\n" + " " + "\n";

    private static void reclassifyAllEntriesTask() {
        System.out.println("Reclassifying all entries in database...");
        DatabaseHelper.reClassifyAllEntryes();
        System.out.println("Entries correctly reclassified - Database has been updated\n");
        DatabaseHelper.printDatasetStats();

    }

    private  static void deleteDatabaseTask() {
        System.out.println(" Insert Y to confirm database deletion, N to cancel");
        Scanner inputScanner = new Scanner(System.in);
        boolean success = false;
        if(inputScanner.next().equalsIgnoreCase("y")) {
            System.out.println("Deleting Database");
            success = DatabaseHelper.deleteDatabase();


            if (success)
                System.out.println("Database deleted!");
            else
                System.err.println("ERROR:\tCan't delete dabase file");

            DatabaseHelper.createDatabase();

        }
        else {
            System.out.println("Database deletion canceled");
        }

    }

    private static void directoryAnalysisTask(boolean forceReinsert,String folderPath, String zipPassword) {
        boolean validpassword = zipPassword != null;
        if (forceReinsert) {
            RequestSender r = new RequestSender(forceReinsert);
            System.out.println("force_reinsert = "+ forceReinsert );
            if(validpassword)
                r.postFileList(folderPath,zipPassword);
            else
                r.postFileList(folderPath);

        }
        else {

            RequestSender r = new RequestSender();
            if(validpassword)
                r.postFileList(folderPath,zipPassword);
            else
                r.postFileList(folderPath);

        }
    }

    private static void md5ListAnalysisTask(boolean forceReinsert,String folderPath) {
        if (forceReinsert) {
            RequestSender r = new RequestSender(forceReinsert);
            System.out.println("force_reinsert = "+ forceReinsert );
            r.postMD5ListRequest(folderPath);

        }
        else {

            RequestSender r = new RequestSender();
            r.postMD5ListRequest(folderPath);
        }
    }

    private static void deleteAllUnzippedFile() {
        FileUtils.deleteAllUnzippedFiles();
    }

    private static void generateConfigJson(String filepath) {
        if (filepath == null)
            FileUtils.generateConfigJSON();
        else
            FileUtils.generateConfigJSON(filepath);
    }

    private static void dumpDatabaseToJsonTask(String filepath) {
        if (filepath == null) {
            System.out.println("Dumping database..");
            DatabaseHelper.generateJSON();

        }
        else {
            System.out.println("Dumping database...");
            DatabaseHelper.generateJSON(filepath);
        }


    }

    private static void printAppInformationTask(Options options) {

        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(180);
        System.out.println();
        formatter.printHelp( "EvilBox", appHeader, options, appFooter, true);

    }

    public static void main (String[] args) {

        CommandLineParser parser = new DefaultParser();
        Options options = ArgumentOptions.getApplicationOptions();
        boolean forceReinsert = false;
        String zipPassword = null;


        try {
            // parse the command line arguments
            CommandLine line = parser.parse(options, args);

            if (line.hasOption(ArgumentOptions.HELP_OPT)) {
                printAppInformationTask(options);
                System.exit(0);
            }

            System.out.print(appHeader);
            FileUtils.createDirectoryStructure(); //todo rimuovere la creazione automatica di evilbox_cfg.json

            if (line.hasOption(ArgumentOptions.REANALYZE_DATABASE_OPT))
                reclassifyAllEntriesTask();

            if (line.hasOption(ArgumentOptions.DELETE_DATABASE_OPT))
                deleteDatabaseTask();

            if (line.hasOption(ArgumentOptions.FORCE_REINSERT_OPT))
                forceReinsert = true;

            if (line.hasOption(ArgumentOptions.ZIP_PASSWORD_OPT))
                zipPassword = line.getOptionValue(ArgumentOptions.ZIP_PASSWORD_OPT);

            if (line.hasOption(ArgumentOptions.DUMP_CONFIG_OPT))
                generateConfigJson(line.getOptionValue(ArgumentOptions.DUMP_CONFIG_OPT));

            if (line.hasOption(ArgumentOptions.DIR_ANAlYSIS_OPT)) {
                String folderPath = line.getOptionValue(ArgumentOptions.DIR_ANAlYSIS_OPT);
                directoryAnalysisTask(forceReinsert, folderPath, zipPassword);
            }

            if (line.hasOption(ArgumentOptions.MD5_ANAlYSIS_OPT)) {
                String jsonDir = line.getOptionValue(ArgumentOptions.MD5_ANAlYSIS_OPT);
                md5ListAnalysisTask(forceReinsert,jsonDir);
            }

            if (line.hasOption(ArgumentOptions.DUMP_DATABASE_OPT)) {
                String targetPath = line.getOptionValue(ArgumentOptions.DUMP_DATABASE_OPT);
                dumpDatabaseToJsonTask(targetPath);
            }

            if (line.hasOption(ArgumentOptions.DELETE_ZIP_OPT)) {
                deleteAllUnzippedFile();
            }
        }
        catch (ParseException exp) {
            // oops, something went wrong
            System.out.println();
            System.err.println( "Parsing failed.  Reason: " + exp.getMessage() );
            printAppInformationTask(options);
        }
    }
}
