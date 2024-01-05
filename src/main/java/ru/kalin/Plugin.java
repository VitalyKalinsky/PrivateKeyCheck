package ru.kalin;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Mojo(name = "checkPrivateKeys")
public class Plugin extends AbstractMojo {
    @Parameter(property = "filesToCheck", required = true, readonly = true)
    String[] filesToCheck;

    @Parameter(property = "directoriesToCheck", required = true, readonly = true)
    String[] directoriesToCheck;

    private static final LinkedList<Found> found = new LinkedList<>();

    @Override
    public void execute() {
        LinkedHashSet<File> files = new LinkedHashSet<>();
        Arrays.stream(filesToCheck).forEach(fileName -> files.add(new File(fileName)));
        Arrays.stream(directoriesToCheck)
                .map(dirName -> new File(dirName).listFiles())
                .filter(Objects::nonNull)
                .forEach(dirFiles -> files.addAll(Arrays.asList(dirFiles)));
        System.out.println("Checking files:");
        files.forEach(this::checkFile);
        if (found.isEmpty())
            System.out.println("No private info found");
        else {
            System.out.println("Found private info");
            found.sort(Found::compareTo);
            found.forEach(el -> System.out.printf("      at %s:%d with probability %d\n", el.getFileName(), el.getLine(), el.getKeyChance()));
        }

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
        byte chance = getChanceRexex(line, sign);
        byte hasSuspicious = (byte) (line.matches(".*(password|api|login|username|passwd|user)+.*") ? 2 : 0);
        if (chance + hasSuspicious >= 1) {
            found.add(new Found(file.getAbsolutePath(), i + 1, chance + hasSuspicious));
        }
    }

    private byte getChanceRexex(String line, char sign) {
        Pattern arg = Pattern.compile(sign + "(.*?)" + sign);
        Matcher matcher = arg.matcher(line);
        byte chance = 0;
        while (matcher.find()) {
            String match = matcher.group(0);
            String pass = match.substring(match.indexOf(sign) + 1, match.lastIndexOf(sign)).strip();
            byte curChance = getChance(pass);
            if (curChance > chance)
                chance = curChance;
        }
        return chance;
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

            byte chance = getChanceRexex(line, sign);

            if (count == 2) {
                String pass = line.substring(line.indexOf(">") + 1, line.lastIndexOf("<")).strip();
                byte curChance = getChance(pass);
                if (curChance > chance)
                    chance = curChance;
            }

            //adding to found list
            byte hasSuspicious = (byte) (line.matches(".*(password|api|login|username|passwd|user)+.*") ? 2 : 0);
            if (chance + hasSuspicious >= 1) {
                found.add(new Found(file.getAbsolutePath(), i + 1, chance + hasSuspicious));
            }


        } else {
            byte chance = getChance(line.trim());
            //adding to found list
            byte hasSuspicious = (byte) (line.matches(".*(password|api|login|username|passwd|user)+.*") ? 2 : 0);
            if (chance + hasSuspicious >= 1) {
                found.add(new Found(file.getAbsolutePath(), i + 1, chance + hasSuspicious));
            }
        }
    }

    byte getChance(String pass) {
        byte chance = 0;
        if (pass.matches("[\\w:!@.#$%&*()=\\-+]+")) {
            chance += 1;
            if (pass.length() >= 8) {
                chance += 2;
            }
            double entropy = entropy(pass);
            if (entropy >= 3) {
                chance += Math.round(2 + entropy);
            }
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

