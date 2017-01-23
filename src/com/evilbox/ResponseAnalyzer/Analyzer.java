package com.evilbox.ResponseAnalyzer;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.VirusScanInfo;

import java.util.*;

/**
 * Created by Mick on 10/09/2016.
 */
public class Analyzer {

    private final String[] truncateAfter = {"Norman", "Avast", "Avira", "McAffee-GW-Edition", "McAffee", "Kaspersky",
                                            "ESET-NOD32", "Fortinet", "Jiangmin", "Comodo", "GData", "Avast", "Sophos",
                                            "TrendMicro-HouseCall", "TrendMicro", "NANO-Antivirus", "Microsoft"};
    private ArrayList<String> truncate = new ArrayList<>(Arrays.asList(truncateAfter));
    private HashMap<String, String> infectionVectors;
    private HashMap<String, String> behaviourAlias;

    private String[] behaviours = {"virus", "rootkit", "worm", "trojan", "backdoor"}; // used by analyzer version 1

    // all secondary goals of our classification
    private String[] malwareGoals = {"ddos","arcbomb","sms" ,"banker", "game-thief","fake-av", "mail-finder",
            "ransom","cryptolocker", "clicker",  "proxy", "im","password","email", "keylogger","downloader"};

    private String[] secondaryMalwareGoalsAliases = {"stealer","spy","arcbomb","sms" ,"banker", "game-thief","fake-av",
            "mail-finder","ransom","cryptolocker", "clicker",  "proxy", "im","password","email", "keylogger","downloader"};

    private HashMap<String,String> malwareGoalsGrouping; // used by analyzer version 1


    private HashMap<String, Integer> behaviourRank;
    private HashMap<String, Integer> infectionVectorRank;
    private HashMap<String, Integer> primaryGoalRank;
    private HashMap<String, Integer> secondaryGoalRank;

    // beahviour che contengono informazioni specifiche sul secondary goal
    private String[] trojanGoalsAware = {"trojan-arcbomb", "trojan-banker", "trojan-clicker", "trojan-ddos",
                                         "trojan-downloader", "trojan-dropper", "trojan-fakeav", "trojan-gamethief",
                                         "trojan-im", "trojan-mailfinder", "trojan-notifier", "trojan-proxy",
                                         "trojan-psw", "trojan-ransom", "trojan-sms", "trojan-spy" };

    private String[] trojanAliases = {"trojan", "trj", "trojware","tr"};

    // beahaviour che contengono informazioni sull'infection vector
    private String[] wormInfectionAware = {"email-worm", "im-worm", "irc-worm", "net-worm", "p2p-worm" };
    private String[] wormAliases = {"worm","wrm"};
    private String[] virusAliases = {"virus","fileinfector"};
    private String[] rootkitAliases = {"rootkit","rtk"};
    private String[] backdoorAliases = {"backdoor","back","bkdr"};

    private HashMap<String,String> behaviourSecondaryGoalLink;  // linka particolari behaviour a finalità
    private HashMap<String,String> behaviourVectorLink;         // linka behaviour a infection vector
    private HashMap<String,String> secondaryGoalToPrimary;      // linka secondary a primary
    private HashMap<String,String> secondaryGoalAliases;        // alias dei secondary goal


    public Analyzer() {
        init();
    }

    /**
     * Initializes all HashMaps to keep track of token ranking and associations betweem
     * behaviour        - infection vectors
     * behaviour        - secondary goal
     * secondary goal   - primary goal
     */
    private void init() {
        buildInfecDict();
        buildBehaviourAliases();
        buildPrimaryGoals();

        //below init needed by v2 analyzer
        createRankingBehaviour();
        createRankingInfectionVectors();
        createRankingPrimaryGoals();
        createRankingSecondaryGoals();
        createBehaviourVectorLink();
        createBehaviourSecondaryGoalLink();
        createGoalSecondaryToPrimary();
        createSecondaryGoalAliases();

    }

    private void buildPrimaryGoals(){
        // associa a ogni secondary goal il primary goal corrispondente
        malwareGoalsGrouping = new HashMap<>();
        malwareGoalsGrouping.put("ddos","DoS");
        // Arcbomb è associato a più di un primary goal
        malwareGoalsGrouping.put("arcbomb","DoS");
        malwareGoalsGrouping.put("sms","Theft");
        malwareGoalsGrouping.put("banker","Theft");
        malwareGoalsGrouping.put("game-thief","Theft");
        malwareGoalsGrouping.put("fake-av","Theft");
        // keylogger è associato a più di un primary goal
        malwareGoalsGrouping.put("keylogger","Theft");
        malwareGoalsGrouping.put("email-finder","Theft");
        malwareGoalsGrouping.put("ransom","extorsion");
        malwareGoalsGrouping.put("cryptolocker","extorsion");
        malwareGoalsGrouping.put("clicker","Frode");
        malwareGoalsGrouping.put("proxy","Spionage");
        malwareGoalsGrouping.put("im","Spionage");
        malwareGoalsGrouping.put("password","Spionage");
        malwareGoalsGrouping.put("email","Spionage");
        malwareGoalsGrouping.put("downloader","Diffusion");
        malwareGoalsGrouping.put("bot-net","remoteControl");
        malwareGoalsGrouping.put("Undefined","Undefined");

    }

    // canali di infezione
    private void buildInfecDict() {
        infectionVectors = new HashMap();
        // P2P aliases
        infectionVectors.put("p2p", "p2p");
        infectionVectors.put("sharing", "p2p");
        infectionVectors.put("share", "p2p");
        // internet
        infectionVectors.put("internet", "Internet");
        infectionVectors.put("net", "Internet");
        infectionVectors.put("web", "Internet");
        infectionVectors.put("js","Internet");
        infectionVectors.put("html","Internet"); //check 8d78af81241366d606759efe5a8bca26 è un mail worm ma tu scrivi internet
        infectionVectors.put("php","Internet");
        // IM
        infectionVectors.put("irc", "irc");
        infectionVectors.put("im", "im");
        //Dropped
        infectionVectors.put("drop", "dropped");
        infectionVectors.put("download", "dropped");
        infectionVectors.put("dropped", "dropped");
        // mail
        infectionVectors.put("mail", "E-mail");
        infectionVectors.put("email", "E-mail");
        infectionVectors.put("e-mail", "E-mail");
        //Drive- Physical
        infectionVectors.put("drive", "drive");
        //App store
        infectionVectors.put("app-store", "app-store");
        infectionVectors.put("app", "app-store");

        //Drive By download
        infectionVectors.put("drive-by-download", "drive-by-download");
        infectionVectors.put("drive", "drive-by-download");
        infectionVectors.put("drive", "drive-by-download");


    }

    // used only by analyzer v1
    private String platformRemoval(String scanLabel) {
        /*remainder operiamo su stringhe senza caratteri maiuscoli*/
        String result = scanLabel.replaceAll("win32", "");
        result = result.replaceAll("win", "");
        result = result.replaceAll("hw32", "");
        result = result.replaceAll("w32", "");
        result = result.replaceAll("win", "");
        result = result.replaceAll("32", "");
        return result;
    }

    /**
     * Removes AV suffixes based on antivirus type.
     * */
    private String suffixRemoval(String antiVirusName, String scanLabel) {

        String result = "";

        if (scanLabel != null) {

            result = scanLabel;
            if (truncate.contains(antiVirusName)) {
                int last_index = scanLabel.lastIndexOf(".");
                if (last_index != -1) {
                    result = scanLabel.substring(0, scanLabel.lastIndexOf("."));

                }
            }
            if (antiVirusName.equals("AVG")) {
                int last_index = scanLabel.lastIndexOf(".");
                if (last_index != -1) {
                    result = scanLabel.substring(0, scanLabel.lastIndexOf("."));

                }
            }
            if (antiVirusName.equals("Agnitum")) {
                int last_index = scanLabel.lastIndexOf("!");
                if (last_index != -1) {
                    result = scanLabel.substring(0, scanLabel.lastIndexOf("!"));

                }
            }
        }

        return result;
    }

    /**
     * Associate each alias to the corresponding behaviour
     */
    private void buildBehaviourAliases() {
        // alias macrocategorie
        behaviourAlias = new HashMap<>();
        behaviourAlias.put("troj", "trojan");
        behaviourAlias.put("trj", "trojan");
        behaviourAlias.put("trojware", "trojan");
        behaviourAlias.put("backdoor", "backdoor");
        behaviourAlias.put("back", "backdoor");
        behaviourAlias.put("bkdr", "backdoor");
    }

    /**
     * Initializes the HashMap to record behaviours rank
     */
    private void createRankingBehaviour(){
        // crea la mappa dei behaviour e setta a zero i punteggi
        behaviourRank = new HashMap<>();
        behaviourRank.put("trojan",0);
        behaviourRank.put("worm",0);
        behaviourRank.put("backdoor",0);
        behaviourRank.put("virus",0);
        behaviourRank.put("rootkit",0);
    }

    /**
     * Initializes the HashMap to record primary goals rank
     */
    private void createRankingPrimaryGoals(){
        // crea la mappa delle finalità primarie e setta a zero i punteggi
        primaryGoalRank = new HashMap<>();
        primaryGoalRank.put("dos",0);
        primaryGoalRank.put("furto",0);
        primaryGoalRank.put("estorsione",0);
        primaryGoalRank.put("sabotaggio",0); //check
        primaryGoalRank.put("spionaggio",0);
        primaryGoalRank.put("diffusione",0);
        primaryGoalRank.put("controllo-remoto",0);
        primaryGoalRank.put("proof",0);

    }

    /**
     * Initializes the HashMap to record secondary goals rank
     */
    private void createRankingSecondaryGoals(){
        // crea la mappa delle finalità secondarie e setta a zero i punteggi
        secondaryGoalRank = new HashMap<>();
        secondaryGoalRank.put("ddos",0);
        secondaryGoalRank.put("sms",0);
        secondaryGoalRank.put("arcbomb",0);
        secondaryGoalRank.put("gamethief",0);
        secondaryGoalRank.put("fakeav",0);
        secondaryGoalRank.put("email-finder",0);
        secondaryGoalRank.put("ransom",0);
        secondaryGoalRank.put("cryptolocker",0);
        secondaryGoalRank.put("clicker",0);
        secondaryGoalRank.put("proxy",0);
        secondaryGoalRank.put("im",0);
        secondaryGoalRank.put("password",0);
        secondaryGoalRank.put("keylogger",0);
        secondaryGoalRank.put("downloader",0);
        secondaryGoalRank.put("bot-net",0);

    }

    /**
     * Initializes the HashMap to record Infection vectors rank
     */
    private void createRankingInfectionVectors(){
        //crea la mappa dei vettori di infezione e setta a zero i punteggi
        infectionVectorRank = new HashMap<>();
        infectionVectorRank.put("mail",0);
        infectionVectorRank.put("drive",0);
        infectionVectorRank.put("internet",0);
        infectionVectorRank.put("p2p",0);
        infectionVectorRank.put("im",0);
        infectionVectorRank.put("app-store",0);
        infectionVectorRank.put("dropped",0);
        infectionVectorRank.put("drive-by-download",0);

    }

    /**
     * Create a link between a behaviour and a secondary goal:
     * a label like "trojan-proxy" has info linked to its secondary goal.
     */
    private void createBehaviourSecondaryGoalLink(){
        // crea un'associazione tra behaviour e goal secondari NB: per ora solo per trojan
        behaviourSecondaryGoalLink = new HashMap<>();
        behaviourSecondaryGoalLink.put("trojan-arcbomb", "arcbomb");
        behaviourSecondaryGoalLink.put("trojan-banker", "password");
        behaviourSecondaryGoalLink.put("trojan-clicker", "clicker");
        behaviourSecondaryGoalLink.put("trojan-ddos", "ddos");
        behaviourSecondaryGoalLink.put("trojan-downloader", "downloader");
        behaviourSecondaryGoalLink.put("trojan-dropper", "downloader");
        behaviourSecondaryGoalLink.put("trojan-fakeav", "fakeav");
        behaviourSecondaryGoalLink.put("trojan-gamethief", "gamethief");
        behaviourSecondaryGoalLink.put("trojan-im", "im");
        behaviourSecondaryGoalLink.put("trojan-mailfinder", "email-finder");
        //behaviourSecondaryGoalLink.put("trojan-notifier", "notifier");
        behaviourSecondaryGoalLink.put("trojan-proxy", "proxy");
        behaviourSecondaryGoalLink.put("trojan-pws", "password");
        behaviourSecondaryGoalLink.put("trojan-psw", "password");
        behaviourSecondaryGoalLink.put("trojan-ransom", "ransom");
        behaviourSecondaryGoalLink.put("trojan-sms", "sms");
        behaviourSecondaryGoalLink.put("trojan-spy", "keylogger");// todo change?

    }

    /**
     * Creates an association between a behaviour label and an infection vector
     * a label like "net-worm" contains info about infection vector
     */
    private void createBehaviourVectorLink(){
        //crea un'associazione tra behaviour e vettori di infezione
        behaviourVectorLink = new HashMap<>();
        behaviourVectorLink.put("email-worm","mail");
        behaviourVectorLink.put("irc-worm","irc");
        behaviourVectorLink.put("im-worm","im");
        behaviourVectorLink.put("p2p-worm","p2p");
        behaviourVectorLink.put("net-worm","internet");
        behaviourVectorLink.put("mailworm","mail");
    }

    /**
     * Associates each secondary goal to the primary
     */
    private void createGoalSecondaryToPrimary(){
        // crea un'associazione tra goal secondari e primari
        secondaryGoalToPrimary = new HashMap<>();
        secondaryGoalToPrimary.put("ddos","dos");
        secondaryGoalToPrimary.put("arcbomb","dos");

        secondaryGoalToPrimary.put("notifier","diffusione");
        secondaryGoalToPrimary.put("downloader","diffusione");
        secondaryGoalToPrimary.put("proxy","diffusione");
        secondaryGoalToPrimary.put("dloader","diffusione");
        secondaryGoalToPrimary.put("multidropper","diffusione");
        secondaryGoalToPrimary.put("dropper","diffusione");

        secondaryGoalToPrimary.put("banker","furto");
        secondaryGoalToPrimary.put("pwsbanker","furto");
        secondaryGoalToPrimary.put("onlinegames","furto");
        secondaryGoalToPrimary.put("password","spionaggio");
        secondaryGoalToPrimary.put("wsgames","furto");
        secondaryGoalToPrimary.put("ogame","furto");
        secondaryGoalToPrimary.put("gamethief","furto");

        secondaryGoalToPrimary.put("ransom","estorsione");
        secondaryGoalToPrimary.put("cryptolocker","estorsione");


        secondaryGoalToPrimary.put("mailfinder","spionaggio");
        secondaryGoalToPrimary.put("spy","spionaggio");
        secondaryGoalToPrimary.put("pws","spionaggio");
        secondaryGoalToPrimary.put("psw","spionaggio");
        secondaryGoalToPrimary.put("pwstealer","spionaggio");
        secondaryGoalToPrimary.put("formspy","spionaggio");
        secondaryGoalToPrimary.put("adspy","spionaggio");
        secondaryGoalToPrimary.put("keylogger","spionaggio");

        secondaryGoalToPrimary.put("irc-bot","controllo-remoto");
        secondaryGoalToPrimary.put("spambot","controllo-remoto");
        secondaryGoalToPrimary.put("rbot","controllo-remoto");
        secondaryGoalToPrimary.put("sbot","controllo-remoto");


    }

    /**
     * Create a map with secondary goal aliases
     */
    private void createSecondaryGoalAliases(){
        // crea una lista di alias di goal secondari
        secondaryGoalAliases = new HashMap<>();
        secondaryGoalAliases.put("ddos","ddos");
        secondaryGoalAliases.put("arcbomb","arcbomb");

        //secondaryGoalAliases.put("notifier","diffusione");
        secondaryGoalAliases.put("downloader","downloader");
        secondaryGoalAliases.put("proxy","downloader");
        secondaryGoalAliases.put("dloader","downloader");
        secondaryGoalAliases.put("multidropper","downloader");
        secondaryGoalAliases.put("dropper","downloader");

        //secondaryGoalAliases.put("banker","furto");
        secondaryGoalAliases.put("pwsbanker","password");
        secondaryGoalAliases.put("onlinegames","gamethief");
        secondaryGoalAliases.put("password","password");
        secondaryGoalAliases.put("wsgames","gamethief");
        secondaryGoalAliases.put("ogame","gamethief");
        secondaryGoalAliases.put("gamethief","gamethief");

        secondaryGoalAliases.put("ransom","ransom");
        secondaryGoalAliases.put("cryptolocker","criptolocker");
        secondaryGoalAliases.put("locker","ransom");



        secondaryGoalAliases.put("mailfinder","email-finder");
        //secondaryGoalAliases.put("spy","spionaggio");
        secondaryGoalAliases.put("pws","password");
        secondaryGoalAliases.put("psw","password");
        secondaryGoalAliases.put("pwstealer","password");
        //secondaryGoalAliases.put("formspy","spionaggio");
        //secondaryGoalAliases.put("adspy","spionaggio");
        secondaryGoalAliases.put("keylogger","keylogger");

        secondaryGoalAliases.put("irc-bot","bot-net");
        secondaryGoalAliases.put("spambot","ddos");
        secondaryGoalAliases.put("rbot","bot-net");
        secondaryGoalAliases.put("sbot","bot-net");
    }

    /**
     * Returns the highest ranked token in the HashMap.
     *
     * @param rankingHashmap String, Integer HashMap, it associates each token
     *                       with a number representing it's frequency
     *
     * @return highest ranked token
     */
    private String findMostFrequentToken(HashMap<String, Integer> rankingHashmap) {
        int maxRankMacroValue = 0;
        String most_frequent_macrocategoria = "";
        //trova il token + frequente- costo n
        for (HashMap.Entry<String, Integer> entry : rankingHashmap.entrySet()) {
            if (entry.getValue() > maxRankMacroValue) {
                maxRankMacroValue = entry.getValue();
                most_frequent_macrocategoria = entry.getKey();
            }
        }
        return most_frequent_macrocategoria;
    }

    /** Utilized by version one of responseAnalyzer
     *
     * @param rankingHashMap String, Integer HashMap, it associates each token
     *                       with a number representing it's frequency
     * @return most probable secondary goals String
     */
    private String findSecondaryGoals(HashMap<String,Integer> rankingHashMap){
        /* cerca se sono presenti parole chiave corrispondenti ai secondary goal nella lista dei token
         generata a partire dalle scansioni dei vari av e ritorna quello con rank maggiore
         TODO:ritornare + valori concatenati
          */
        int secondaryGoalRanking = 0;
        String currentSecondaryGoal = "";
        for(String goal : malwareGoals){
            if(rankingHashMap.get(goal.toLowerCase()) != null && rankingHashMap.get(goal.toLowerCase()) > secondaryGoalRanking){
                currentSecondaryGoal = goal.toLowerCase();
                secondaryGoalRanking = rankingHashMap.get(goal.toLowerCase());
            }
        }
        if(currentSecondaryGoal.equals(""))
            currentSecondaryGoal = "Undefined";
        return currentSecondaryGoal;
    }

    /**
     * First version of response analyzer.
     * Return a label containing information of classified sample.
     * A label is a string with te following strcuture:
     * [Behaviour]_[Infection Vector]_[Primary goal]:[Secondary goal]
     * e.g. worm_email_spionaggio:email
     *
     * @param fileScanReport fileScanReport obtained from a virustotal API response
     * @return label assigned to sample associated to fileScanReport supplied
     */
    public String responseAnalyzer(FileScanReport fileScanReport) {

        if(fileScanReport.getPositives() == 0){
            return "not-a-virus";
        }
        Set<Map.Entry<String, VirusScanInfo>> scanInfos = fileScanReport.getScans().entrySet();

        HashMap<String, Integer> rankingHashmap = new HashMap<>();

        for (Map.Entry<String, VirusScanInfo> scan : scanInfos) {

            /*per ogni risultato di scansione
             1-rimuoviamo i suffissi
             2-rendiamo il label minuscolo
             */
            String scanLabel = scan.getValue().getResult();
            if(scanLabel!=null){
                scanLabel = scanLabel.toLowerCase();
            }
            else {
                continue;
            }
            String avName = scan.getKey();
            scanLabel = suffixRemoval(avName, scanLabel);

            scanLabel = platformRemoval(scanLabel);
            scanLabel = scanLabel.toLowerCase();
            ArrayList<String> tokensList = new ArrayList<>(Arrays.asList(scanLabel.split("[^0-9a-zA-Z]")));

            for (String currentToken : tokensList) {
                //salta i token di una sola lettera
                if (currentToken.length() < 2 || currentToken.matches("[0-9]+")) {
                    continue;
                }
                if (tokensList.indexOf(currentToken) == 0) {
                    /*se il token è il primo della lista gli do più peso*/
                    if (rankingHashmap.containsKey(currentToken)) {
                        rankingHashmap.put(currentToken, rankingHashmap.get(currentToken) + 5);
                    } else {
                        rankingHashmap.put(currentToken, 5);
                    }
                    continue;
                }
                if (rankingHashmap.containsKey(currentToken)) {
                    rankingHashmap.put(currentToken, rankingHashmap.get(currentToken) + 1);
                } else {
                    rankingHashmap.put(currentToken, 5);
                }
            }
        }
        /*-------------STAMPA------------------------*/
        /*for (HashMap.Entry<String, Integer> entry : rankingHashmap.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue().toString() + "");
        }*/

        String secondaryGoal="";
        secondaryGoal = findSecondaryGoals((HashMap<String, Integer>) rankingHashmap.clone());


        /*-----------------------------------------------------------------*/
        /*Cerca infection Vector*/
        /*-----------------------------------------------------------------*/
        int max_inf_int = 0; //massimo valore occorrenze termine canale infezione
        String best_inf_candidate = "";
        for (String inf_keyword : infectionVectors.keySet()) {

            if (rankingHashmap.containsKey(inf_keyword)) {
                //se abbiamo un infection channel salviamo il rank, e passiamo al successivo in
                // modo da prendere sempre il + frequente
                if (rankingHashmap.get(inf_keyword) > max_inf_int) {
                    max_inf_int = rankingHashmap.get(inf_keyword); //nuovo max
                    best_inf_candidate = infectionVectors.get(inf_keyword); // nuovo infection channels;
                }
            }

        }

        /*-----------------------------------------------------------------*/
        /*      Cerca Behaviour                                            */
        /*-----------------------------------------------------------------*/
        ArrayList behaviourList = new ArrayList(Arrays.asList(behaviours));
        String most_frequent_behaviour = "Undefined";
        // con i tre token + frequenti fai la ricerca
        //TODO SOMMARE I PUNTEGGI DEI VARI ALIAS, ES: TRJ = TROJAN
        for (int i = 0; i < rankingHashmap.size(); i++) {

            most_frequent_behaviour = findMostFrequentToken(rankingHashmap);
            //il + frequente appartiene a una macro categoria?
            if (!behaviourList.contains(most_frequent_behaviour)) {
                //se il token  piu frequente non appartiene alla lista di macrocategorie cerco negli alias
                if(behaviourAlias.get(most_frequent_behaviour) != null){
                    most_frequent_behaviour = behaviourAlias.get(most_frequent_behaviour);
                    break;
                }
                rankingHashmap.remove(most_frequent_behaviour); //brutal side effect;
                continue;

            }
        }

        //TODO AGGIUNGERE UN CHECK PER VEDERE SE IL BEHAVIOUR SCELTO APPARTIENE ALLA LISTA DEI NOSTRI


        //nessuna informazione sui modi di propagazione
        if (best_inf_candidate.equalsIgnoreCase("")) {
            best_inf_candidate = "Undefined";
        }
        /*------------------------------------------------------------*/

        /*---------------------------------------------------/
        cerca di capire il primary goal se secondary non è undefined
         */

        String primaryGoal ="";
        primaryGoal = malwareGoalsGrouping.get(secondaryGoal);
        if(primaryGoal==null)
            primaryGoal = "Undefined";


        return most_frequent_behaviour + "_" + best_inf_candidate + "_" + primaryGoal + ":" + secondaryGoal;



    }

    /**
     * Version 2 of response analyzer.
     * Return a label containing information of classified sample.
     * A label is a string with te following strcuture:
     * [Behaviour]_[Infection Vector]_[Primary goal]:[Secondary goal]
     * e.g. worm_email_spionaggio:email
     *
     * @param fileScanReport fileScanReport obtained from a virustotal API response
     * @return label assigned to sample associated to fileScanReport supplied
     */
    public String responseAnalyzerV2(FileScanReport fileScanReport ){ //todo check if filescanreport is not null
        if (fileScanReport == null) {
            return "ERROR: request report again";
        }

        if(fileScanReport.getPositives() == 0){
            return "not-a-virus";
        }

        Set<Map.Entry<String, VirusScanInfo>> scanInfos = fileScanReport.getScans().entrySet();
        HashMap<String, Integer> rankingHashmap = new HashMap<>();
        init();
        for (Map.Entry<String, VirusScanInfo> scan : scanInfos) {
            String scanLabel = scan.getValue().getResult();
            if(scanLabel!=null){
                scanLabel = scanLabel.toLowerCase();
            }
            else {
                continue;
            }
            String avName = scan.getKey();
            scanLabel = suffixRemoval(avName, scanLabel);
            // cerca se il label contiene un behaviour legato a un goal
            boolean firstTrojanLabel = true;
            for(String behaviour : trojanGoalsAware){
                if(scanLabel.contains(behaviour.toLowerCase())) {
                    if (firstTrojanLabel) {
                        //aggiorno il rank del behaviour una sola volta
                        int rank = behaviourRank.get("trojan");
                        behaviourRank.put("trojan", rank + 1);
                        firstTrojanLabel = false;
                    }
                    //aggiorno il goal ad esso legato
                    String secondaryGoal = behaviourSecondaryGoalLink.get(behaviour.toLowerCase());
                    int goalRank = secondaryGoalRank.get(secondaryGoal);
                    secondaryGoalRank.put(secondaryGoal, goalRank + 10);

                }
            }

            for(String alias : trojanAliases){
                if(scanLabel.contains(alias) && firstTrojanLabel){
                    int rank = behaviourRank.get("trojan");
                    behaviourRank.put("trojan",rank+1);
                    firstTrojanLabel = false;
                }
            }
            for(String behaviour : wormInfectionAware){
                if(scanLabel.contains(behaviour.toLowerCase())){
                    //aggiorno il rank del behaviour
                    int rank = behaviourRank.get("worm");
                    behaviourRank.put("worm",rank+1);
                    //aggiorno il goal ad esso legato
                    String infectionVector = behaviourVectorLink.get(behaviour.toLowerCase());
                    int infectionRank = infectionVectorRank.get(infectionVector);
                    infectionVectorRank.put(infectionVector,infectionRank + 10);

                }
            }
            for (String alias : wormAliases){
                if(scanLabel.contains(alias)){
                    int rank = behaviourRank.get("worm");
                    behaviourRank.put("worm",rank+1);
                }
            }
            for(String alias : virusAliases){
                if(scanLabel.contains(alias)){
                    int rank = behaviourRank.get("virus");
                    behaviourRank.put("virus",rank+1);
                }
            }
            for(String alias : backdoorAliases){
                if(scanLabel.contains(alias)){
                    int rank = behaviourRank.get("backdoor");
                    behaviourRank.put("backdoor",rank+1);
                }
            }
            for(String alias : rootkitAliases){
                if(scanLabel.contains(alias)){
                    int rank = behaviourRank.get("rootkit");
                    behaviourRank.put("rootkit",rank+1);
                }
            }

            // qui usiamo il vecchio metodo
            ArrayList<String> tokensList = new ArrayList<>(Arrays.asList(scanLabel.split("[^0-9a-zA-Z]")));
            for (String currentToken : tokensList) {
                //salta i token di una sola lettera
                if (currentToken.length() < 2 || currentToken.matches("[0-9]+")) {
                    continue;
                }
                if (tokensList.indexOf(currentToken) == 0) {
                    /*se il token è il primo della lista gli do più peso*/
                    if (rankingHashmap.containsKey(currentToken)) {
                        rankingHashmap.put(currentToken, rankingHashmap.get(currentToken) + 5);
                    } else {
                        rankingHashmap.put(currentToken, 5);
                    }
                    continue;
                }
                if (rankingHashmap.containsKey(currentToken)) {
                    rankingHashmap.put(currentToken, rankingHashmap.get(currentToken) + 1);
                } else {
                    rankingHashmap.put(currentToken, 5);
                }
            }
        }
        /* todo aggiungiamo un check su una variabile per
        capire se abbiamo avuto diverse occorrenze di behaviour con info legate a infection vector e/o
         primary-secondary goal
         */

        for(String infVector : infectionVectorRank.keySet()){
            if(rankingHashmap.containsKey(infVector)){
                int oldRank = infectionVectorRank.get(infVector);
                int rank = rankingHashmap.get(infVector); //prendo il punteggio

                infectionVectorRank.put(infVector,oldRank+rank);
            }
        }
        for(String secGoalAlias : secondaryGoalAliases.keySet()){
            if(rankingHashmap.containsKey(secGoalAlias)){
                String secGoal = secondaryGoalAliases.get(secGoalAlias);
                int oldRank = secondaryGoalRank.get(secondaryGoalAliases.get(secGoalAlias));
                int rank = rankingHashmap.get(secGoalAlias);
                secondaryGoalRank.put(secGoal,oldRank+rank);
            }
        }

        String behaviour = findMostFrequentToken(behaviourRank);
        String infectionVector = findMostFrequentToken(infectionVectorRank);
        String secondaryGoal = findMostFrequentToken(secondaryGoalRank);
        String primaryGoal = secondaryGoalToPrimary.get(secondaryGoal);
        if(secondaryGoal == null || secondaryGoal.equals("")){
            secondaryGoal = "undefined";
        }
        if(infectionVector == null || infectionVector.equals("")){
            infectionVector = "undefined";
        }
        if(primaryGoal == null || primaryGoal.equals("")){
            primaryGoal = "undefined";
        }
        if(behaviour == null || behaviour.equals("")){
            behaviour = "undefined";
        }

        String label =  behaviour+"_"+infectionVector+"_"+primaryGoal+":"+secondaryGoal;
        return label;
    }
}
