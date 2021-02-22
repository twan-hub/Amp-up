package com.ampup.Ampup.models;

import javax.persistence.Entity;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;

@Entity
public class Song extends AbstractEntity{

    @ManyToMany
    private List<Playlist> playlists = new ArrayList<>();

    @NotBlank
    private String title;
    @NotBlank
    private String genre;
    @NotBlank
    private String link;
    @NotBlank
    private String artist;

    public Song(){

    }



    public Song(String title, String genre, String link,String artist){
        super();
        this.title=title;
        this.genre=genre;
        this.link=link;
        this.artist=artist;
    }

    public List<Playlist> getPlaylists() {
        return playlists;
    }

    public void setPlaylists(List<Playlist> playlists) {
        this.playlists = playlists;
    }

    public String getArtist() {
        return artist;
    }

    public void setArtist(String artist) {
        this.artist = artist;
    }
    public String getLink() {
        return link;
    }
    public void setLink(String link) {
        this.link = link;
    }

    public String getGenre() {
        return genre;
    }

    public void setGenre(String genere) {
        this.genre = genere;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

}
