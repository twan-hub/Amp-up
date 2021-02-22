package com.ampup.Ampup.models;

import java.util.ArrayList;

public class SongData {


    /**
     * Returns the results of searching the Jobs data by field and search term.
     *
     * For example, searching for employer "Enterprise" will include results
     * with "Enterprise Holdings, Inc".
     *
     * @param column Job field that should be searched.
     * @param value Value of the field to search for.
     * @param allList The list of jobs to search.
     * @return List of all jobs matching the criteria.
     */
    public static ArrayList<Song> findByColumnAndValue(String column, String value, Iterable<Song> allList) {

        ArrayList<Song> results = new ArrayList<>();

        if (value.toLowerCase().equals("all")){
            return (ArrayList<Song>) allList;
        }

        if (column.equals("all")){
            results = findByValue(value, allList);
            return results;
        }
        for (Song song : allList) {

            String aValue = getFieldValue(song, column);

            if (aValue != null && aValue.toLowerCase().contains(value.toLowerCase())) {
                results.add(song);
            }
        }

        return results;
    }

    public static String getFieldValue(Song song, String fieldName){
        String theValue;
        if (fieldName.equals("title")){
            theValue = song.getTitle();
        } else if (fieldName.equals("genre")){
            theValue = song.getGenre().toString();
        } else if (fieldName.equals("artist")){
            theValue = song.getArtist().toString();
        }else {
            theValue = song.getLink().toString();
        }

        return theValue;
    }

    /**
     * Search all Job fields for the given term.
     *
     * @param value The search term to look for.
     * @param allList The list of jobs to search.
     * @return      List of all jobs with at least one field containing the value.
     */
    public static ArrayList<Song> findByValue(String value, Iterable<Song> allList) {
        String lower_val = value.toLowerCase();

        ArrayList<Song> results = new ArrayList<>();

        for (Song song : allList) {

            if (song.getTitle().toLowerCase().contains(lower_val)) {
                results.add(song);
            } else if (song.getLink().toString().toLowerCase().contains(lower_val)) {
                results.add(song);
            } else if (song.getGenre().toString().toLowerCase().contains(lower_val)) {
                results.add(song);
            } else if (song.getArtist().toString().toLowerCase().contains(lower_val)) {
                results.add(song);
            } else if (song.toString().toLowerCase().contains(lower_val)) {
                results.add(song);
            }

        }

        return results;
    }


}
