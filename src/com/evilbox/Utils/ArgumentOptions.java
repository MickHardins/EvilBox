package com.evilbox.Utils;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * Created by mick on 13/01/17.
 * Questa classe gestisce le opzioni con cui può essere eseguito il programma
 * utilizza Apache CLI per la gestione degli argomenti forniti da command line
 */
public class ArgumentOptions {

    public static final String DIR_ANAlYSIS_OPT = "a";
    public static final String MD5_ANAlYSIS_OPT = "m";
    public static final String DUMP_CONFIG_OPT = "j";
    public static final String DUMP_DATABASE_OPT = "dump_db";
    public static final String ZIP_PASSWORD_OPT = "p";
    public static final String ZIP_PASSWORD_LONG_OPT = "psw";
    public static final String REANALYZE_DATABASE_OPT = "r";
    public static final String DELETE_DATABASE_OPT = "delete_db";
    public static final String DELETE_ZIP_OPT = "z";
    public static final String FORCE_REINSERT_OPT = "f";
    public static final String FORCE_REINSERT_LONG_OPT = "force";
    public static final String HELP_OPT = "h";
    public static final String HELP_LONG_OPT = "help";


    public ArgumentOptions() {}


    public static Options getApplicationOptions() {
        Options options = new Options();

        Option dirAnalysis = Option.builder(DIR_ANAlYSIS_OPT)
                .desc("analyze samples in a directory, if no target is specified the default one will be used")
                .hasArg()
                .optionalArg(true)
                .argName("target-directory")
                .build();

        Option jsonAnalysis = Option.builder(MD5_ANAlYSIS_OPT)
                .desc("analyze md5 from scraped json files, if no target is specified the default one will be used")
                .hasArg()
                .optionalArg(true)
                .argName("target-directory")
                .build();

        Option configDump = Option.builder(DUMP_CONFIG_OPT)
                .desc("create "+FileUtils.EVILBOX_CONFIG_JSON_NAME+" file and place it in target directory, if no target is specified, file will be placed in app's working directory ")
                .hasArg()
                .optionalArg(true)
                .argName("target-directory")
                .build();

        Option databaseToJson= Option.builder(DUMP_DATABASE_OPT)
                .desc("create a json representation of database and place it in target dir, if no target is specified the default one will be used ")
                .hasArg()
                .optionalArg(true)
                .argName("target-directory")
                .build();

        Option zipPassword = Option.builder(ZIP_PASSWORD_OPT)
                .longOpt(ZIP_PASSWORD_LONG_OPT)
                .desc("insert password to decrypt .zip files in samples directory")
                .hasArg()
                .argName("zip-password")
                .optionalArg(false)
                .build();

        Option help = Option.builder(HELP_OPT)
                .longOpt(HELP_LONG_OPT)
                .desc("print help and exit")
                .build();

        Option reanalyzeDB = new Option(REANALYZE_DATABASE_OPT, false, "run analysis on all entries in database");
        Option deleteDatabase = new Option(DELETE_DATABASE_OPT, "delete database");
        Option deleteZipfile = new Option(DELETE_ZIP_OPT,"delete all files unzipped during analysis, the entire /unzippped folder will be cleaned");
        Option forceDBreinsert = new Option(FORCE_REINSERT_OPT,FORCE_REINSERT_LONG_OPT,false,"force a new VirusTotal request, even if samples are already saved in database");



        options.addOption(dirAnalysis);
        options.addOption(jsonAnalysis);
        options.addOption(configDump);
        options.addOption(databaseToJson);
        options.addOption(zipPassword);
        options.addOption(reanalyzeDB);
        options.addOption(deleteDatabase);
        options.addOption(deleteZipfile);
        options.addOption(forceDBreinsert);
        options.addOption(help);

        return options;
    }
}
