package ru.kalin;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Mojo(name = "findAPIKeys")
public class Plugin extends AbstractMojo {
    @Parameter(property = "filesToCheck", required = true, readonly = true)
    String[] filesToCheck;

    @Parameter(property = "probability", readonly = true, defaultValue = "5")
    String probability;

    private static final LinkedList<Found> found = new LinkedList<>();

    @Override
    public void execute() {
        LinkedHashSet<File> files = new LinkedHashSet<>();
        int iProbability = Math.min(Integer.parseInt(probability), 10);
        Arrays.stream(filesToCheck)
                .map(File::new)
                .forEach(dir -> files.addAll(recFile(dir)));

        files.forEach(this::checkFile);
        if (found.isEmpty())
            System.out.println("No private info found");
        else {
            System.out.println("Found private info");
            found.sort(Found::compareTo);
            found.stream()
                    .filter(f -> f.getOutputKeyChance() >= iProbability)
                    .forEach(el -> System.out.printf("      %s at %s:%d with probability %d\n", el.getPassword(), el.getFileName(), el.getLine(), el.getOutputKeyChance()));
        }

    }

    LinkedList<File> recFile(File dir) {
        LinkedList<File> files = new LinkedList<>();
        if (dir.isDirectory()) {
            for (File file : Objects.requireNonNull(dir.listFiles())) {
                if (file.isDirectory()) {
                    files.addAll(recFile(file));
                } else {
                    files.add(file);
                }
            }
        } else
            files.add(dir);
        return files;
    }

    private String getFileExtension(String fName) {
        int index = fName.lastIndexOf('.');
        return index == -1 ? null : fName.substring(index + 1);
    }

    void checkFile(File file) {
        try {
            String extension = getFileExtension(file.getName());
            ArrayList<String> lines = new BufferedReader(
                    new FileReader(file))
                    .lines()
                    .map(String::toLowerCase).collect(Collectors.toCollection(ArrayList::new));

            if (Objects.equals(extension, "xml")) {
                for (int i = 0; i < lines.size(); i++)
                    checkXMLPass(lines.get(i).strip(), i, file);
            } else
                for (int i = 0; i < lines.size(); i++)
                    checkPass(lines.get(i).strip(), i, file);


        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    void checkPass(String line, int i, File file) {
        char sign;
        if (line.matches(".*\".*\".*")) {
            sign = '"';
        } else if (line.matches(".*'.*'.*")) {
            sign = '\'';
        } else
            return;
        String passToAdd = "";
        double chance = 0;
        matchAndAdd(line, i, file, sign, passToAdd, chance);
    }

    private void matchAndAdd(String line, int i, File file, char sign, String passToAdd, double chance) {
        Pattern arg = Pattern.compile(sign + "(.*?)" + sign);
        Matcher matcher = arg.matcher(line);
        while (matcher.find()) {
            String match = matcher.group(0);
            String pass = match.substring(match.indexOf(sign) + 1, match.lastIndexOf(sign)).strip();
            double curChance = getChance(pass);
            if (curChance > chance) {
                chance = curChance;
                passToAdd = pass;
            }
        }
        if (chance >= 1) {
            found.add(new Found(file.getAbsolutePath(), i + 1, chance, passToAdd));
        }
    }

    void checkXMLPass(String line, int i, File file) {
        long count = line.codePoints().filter(ch -> ch == '<').count();
        if (count >= 1) {

            //definition of quotes
            char sign = 0;
            if (line.matches(".*\".*\".*")) {
                sign = '"';
            } else if (line.matches(".*'.*'.*")) {
                sign = '\'';
            }

            String passToAdd = "";
            double chance = 0;

            if (count == 2) {
                String pass = line.substring(line.indexOf(">") + 1, line.lastIndexOf("<")).strip();
                double curChance = getChance(pass);
                if (curChance > chance) {
                    chance = curChance;
                    passToAdd = pass;
                }
            }

            matchAndAdd(line, i, file, sign, passToAdd, chance);


        } else {
            String pass = line.trim();
            double chance = getChance(pass);
            //adding to found list;
            if (chance >= 1) {
                found.add(new Found(file.getAbsolutePath(), i + 1, chance, pass));
            }
        }
    }

    double getChance(String pass) {
        double chance = 0;
        if (pass.matches("[\\w:!@.#$%&*(\\[\\])=\\-+]+") && pass.length() >= 8) {
            double entropy = entropy(pass);
            chance += entropy >= 3 ? Math.log(entropy) * 10 % 10 * 1.9 + 1 : 0;
        }
        return chance;
    }

    double entropy(String str) {
        byte[] fileContent = str.getBytes();

        // create array to keep track of frequency of bytes
        int[] frequency_array = new int[256];
        int fileContentLength = fileContent.length - 1;

        // count frequency of occuring bytes
        for (int i = 0; i < fileContentLength; i++) {
            byte byteValue = fileContent[i];
            frequency_array[Byte.toUnsignedInt(byteValue)]++;
        }

        // calculate entropy
        double entropy = 0;
        for (int j : frequency_array) {
            if (j != 0) {
                // calculate the probability of a particular byte occuring
                double probabilityOfByte = (double) j / (double) fileContentLength;

                // calculate the next value to sum to previous entropy calculation
                double value = probabilityOfByte * (Math.log(probabilityOfByte) / Math.log(2));
                entropy = entropy + value;
            }
        }
        entropy *= -1;
        return entropy;
    }

}

