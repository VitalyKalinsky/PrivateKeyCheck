package ru.kalin;

import com.google.common.collect.LinkedListMultimap;
import com.google.common.collect.Multimap;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;


@Mojo(name = "checkPrivateKeys")
public class Plugin extends AbstractMojo {
    @Parameter(property = "filesToCheck", required = true, readonly = true)
    String[] filesToCheck;

    @Parameter(property = "directoriesToCheck", required = true, readonly = true)
    String[] directoriesToCheck;

    LinkedList<Found> found = new LinkedList<>();

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        LinkedHashSet<File> files = new LinkedHashSet<>();
        Arrays.stream(filesToCheck).forEach(fileName -> files.add(new File(fileName)));
        Arrays.stream(directoriesToCheck)
                .map(dirName -> new File(dirName).listFiles())
                .filter(Objects::nonNull)
                .forEach(dirFiles -> files.addAll(Arrays.asList(dirFiles)));
        System.out.println("Checking files:");
        files.forEach(this::checkNames);
        if (found.isEmpty())
            System.out.println("No private info found");
        else {
            System.out.println("Found private info");
            found.sort(Found::compareTo);
            found.forEach(el -> System.out.printf("      at %s:%d with probability %d\n", el.getFileName(), el.getLine(), el.getKeyChance()));
        }
    }

    void checkNames(File file) {
        try {
            ArrayList<String> lines = new BufferedReader(
                    new FileReader(file))
                    .lines()
                    .map(String::toLowerCase).collect(Collectors.toCollection(ArrayList::new));
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                boolean hasSuspiciousName = line.matches(".*(password|api|login|username|passwd|user)+.*");
                byte chance = checkPass(line);
                if (hasSuspiciousName || chance >= 1) {
                    found.add(new Found(file.getAbsolutePath(), i + 1, hasSuspiciousName ? chance + 2 : chance));
                }
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    static byte checkPass(String line) {
        String pass = "";
        byte chance = 0;
        char quot;
        if (line.matches(".*\".*\".*")) {
            quot = '"';
        } else if (line.matches(".*'.*'.*")) {
            quot = '\'';
        } else
            return chance;

        pass = line.substring(line.indexOf(quot) + 1, line.lastIndexOf(quot)).strip();
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

    static double entropy(String str) {
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
        for (int i = 0; i < frequency_array.length; i++) {
            if (frequency_array[i] != 0) {
                // calculate the probability of a particular byte occuring
                double probabilityOfByte = (double) frequency_array[i] / (double) fileContentLength;

                // calculate the next value to sum to previous entropy calculation
                double value = probabilityOfByte * (Math.log(probabilityOfByte) / Math.log(2));
                entropy = entropy + value;
            }
        }
        entropy *= -1;
        return entropy;
    }

}

