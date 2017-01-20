package com.evilbox.ResponseAnalyzer;

import java.util.ArrayList;

/**
 * Created by Mick on 20/11/2016.
 */
public class ClassifiedSample {

    String md5;
    String behaviour;
    String label;
    String infectionVector;
    ArrayList<String> primaryGoal;
    ArrayList<String> secondaryGoal;

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getBehaviour() {
        return behaviour;
    }

    public void setBehaviour(String behaviour) {
        this.behaviour = behaviour;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getInfectionVector() {
        return infectionVector;
    }

    public void setInfectionVector(String infectionVector) {
        this.infectionVector = infectionVector;
    }

    public ArrayList<String> getPrimaryGoal() {
        return primaryGoal;
    }

    public void setPrimaryGoal(ArrayList<String> primaryGoal) {
        this.primaryGoal = primaryGoal;
    }

    public ArrayList<String> getSecondaryGoal() {
        return secondaryGoal;
    }

    public void setSecondaryGoal(ArrayList<String> secondaryGoal) {
        this.secondaryGoal = secondaryGoal;
    }


}
