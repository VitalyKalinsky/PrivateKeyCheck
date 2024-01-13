package ru.kalin;

public class Found implements Comparable<Found>{
    private String fileName;
    private int line;
    private final double keyChance;

    public Found(String fileName, int line, double keyChance) {
        this.fileName = fileName;
        this.line = line;
        this.keyChance = keyChance;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public int getLine() {
        return line;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public double getKeyChance() {
        return keyChance;
    }

    public int getOutputKeyChance(){
        return (int) Math.round(keyChance > 10 ? keyChance - keyChance % 10 : keyChance);
    }

    @Override
    public int compareTo(Found comp) {
        return -Double.compare(getKeyChance(), comp.getKeyChance());
    }
}
