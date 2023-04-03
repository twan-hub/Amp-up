package com.ampup.Ampup.controllers;


import com.ampup.Ampup.models.DTO.LoginFormDTO;
import com.ampup.Ampup.models.DTO.RegisterFormDTO;
import com.ampup.Ampup.models.Ids;
import com.ampup.Ampup.models.Playlist;
import com.ampup.Ampup.models.Song;
import com.ampup.Ampup.models.User;
import com.ampup.Ampup.models.data.PlaylistRepository;
import com.ampup.Ampup.models.data.SongRepository;
import com.ampup.Ampup.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpSession;
import javax.swing.text.html.Option;
import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
public class AmpUpController {

    @Autowired
    private SongRepository songRepository;

    @Autowired
    private AuthenticationService authenticationService;

    private Song song = new Song();

    private Playlist playlist= new Playlist();

    @Autowired
    private PlaylistRepository playlistRepository;

    private Song testSong= new Song("Slow Motion","R&B","Link","Trey");


    @RequestMapping("")
    public User index (Model model, HttpSession session){
        User user=authenticationService.getUserFromSession(session);
        return user;
    }

    @PostMapping("add")
    public Song processAddSongForm(@RequestBody @Valid Song newSong) {

//        if(errors.hasErrors()){
//            model.addAttribute("title", "Add New Song");
//            return "add";
//        }
        songRepository.save(newSong);

        return newSong;
    }

//    @GetMapping("delete")
//    public String displayDeleteSongForm(Model model) {
////        model.addAttribute("title", "Delete Grocery List");
//        model.addAttribute("songs", songRepository.findAll());
//        return "delete";
//    }

    @PostMapping("delete")
    public int processDeleteSongForm(@RequestBody @Valid Ids songIds) {
        int i = 0;
        if (songIds != null) {
            for (int id : songIds.getSongIds()) {
                Iterable<Playlist> playlists=playlistRepository.findAll();
                for(Playlist playlist:playlists){
                    i++;
                    Optional<Song> optSong=songRepository.findById(id);
                    Song song=optSong.get();
                    playlist.deleteSong(song);
                    playlistRepository.save(playlist);

                }
                songRepository.deleteById(id);
            }
            return i;
        }

        return i;
    }

    @GetMapping("edit/{Id}")
    public String displayEditSongForm(Model model, @PathVariable("Id") int Id) {

        Optional optSong = songRepository.findById(Id);
        if (optSong.isPresent()) {
            Song song = (Song) optSong.get();
            model.addAttribute("song", song);
            return "edit";
        } else {
            return "redirect:../";
        }
    }

    @PostMapping("edit/{Id}")
    public String processEditSongForm(@PathVariable("Id") int Id, Model model,@Valid  @ModelAttribute Song song,
                                            Errors errors) {
        if(errors.hasErrors()){
            return"edit";
        }
        Optional<Song> optSong=songRepository.findById(Id);
        if(optSong.isPresent()){
            Song dbSong= optSong.get();
            dbSong.setArtist(song.getArtist());
            dbSong.setGenre(song.getGenre());
            dbSong.setLink(song.getLink());
            dbSong.setTitle(song.getTitle());
            songRepository.save(dbSong);
        }

        return "redirect:../";
    }
    @GetMapping("view/{songId}")
    public Optional displayViewSong(Model model, @PathVariable int songId, HttpSession session) {
        User user=authenticationService.getUserFromSession(session);
        Optional optSong = songRepository.findById(songId);
            return optSong;
    }

    @GetMapping("/all/users")
    public LoginFormDTO displa( LoginFormDTO reg) {
        reg.setPassword("12345678");
        reg.setUsername("arewed");

            return reg;
    }
}
// we did it!gjgjgjgugugugjg