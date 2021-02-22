package com.ampup.Ampup.controllers;

import com.ampup.Ampup.models.Song;
import com.ampup.Ampup.models.SongData;
import com.ampup.Ampup.models.data.SongRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;

@Controller
@RequestMapping("search")
public class SearchController {


    @Autowired
    private SongRepository songRepository;

    static HashMap<String, String> columnChoices = new HashMap<String,String>();

    static {
        columnChoices.put("all","All");
        columnChoices.put("link", "Link");
        columnChoices.put("genre", "Genre");
        columnChoices.put("artist", "Artist");
        columnChoices.put("title","Title");
    }



    @RequestMapping("")
    public String search(Model model) {
        model.addAttribute("columns", columnChoices);
        return "search";
    }

    @PostMapping("results")
    public String displaySearchResults(Model model, @RequestParam String searchType, @RequestParam String searchTerm){
        Iterable<Song> songs;
        if (searchTerm.toLowerCase().equals("all") || searchTerm.equals("")){
            songs = songRepository.findAll();
        } else {
            songs = SongData.findByColumnAndValue(searchType, searchTerm, songRepository.findAll());
        }
        model.addAttribute("columns", columnChoices);
        model.addAttribute("title", "Songs with " + columnChoices.get(searchType) + ": " + searchTerm);
        model.addAttribute("songs", songs);

        return "search";
    }
}
