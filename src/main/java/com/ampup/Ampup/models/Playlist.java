package com.ampup.Ampup.models;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;

@Entity
public class Playlist extends AbstractEntity{

    @NotBlank
    private String name;


    private Integer owner;

    @ManyToMany
    private List<Song> songs=new ArrayList<>();

    public Playlist(){

    }

    public Playlist(String name, List<Song> songs){
        super();
        this.name=name;
        this.songs=songs;
    }

    public void addSong(Song newSong){
        songs.add(newSong);
    }

    public void addAllSongs(Iterable<Song> newSongs){
        for(Song song:newSongs){
            addSong(song);
        }
    }

    public void deleteSong(Song deleteSong){
        songs.remove(deleteSong);
    }
    public void removeDuplicates(List<Song> list)
    {

        // Create a new ArrayList
        List<Song> newList = new ArrayList<>();

        // Traverse through the first list
        for (Song element : list) {

            // If this element is not present in newList
            // then add it
            if (!newList.contains(element)) {

                newList.add(element);
            }
        }

        // return the new list
        songs=newList;
    }

    public List<Song> getSongs() {
        return songs;
    }

    public void setSongs(List<Song> songs) {
        this.songs = songs;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getOwner() {
        return owner;
    }

    public void setOwner(Integer owner) {
        this.owner = owner;
    }

}
