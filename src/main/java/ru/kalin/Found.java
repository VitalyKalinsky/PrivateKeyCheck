package ru.kalin;

public class Found implements Comparable<Found>{
    private String fileName;
    private int line;
    private int keyChance;

    public Found(String fileName, int line, int keyChance) {
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

    public int getKeyChance() {
        return keyChance > 10 ? keyChance - keyChance % 10 : keyChance;
    }

    public void setKeyChance(int keyChance) {
        this.keyChance = keyChance;
    }

    @Override
    public int compareTo(Found comp) {
        return comp.getKeyChance() - getKeyChance();
    }
}
