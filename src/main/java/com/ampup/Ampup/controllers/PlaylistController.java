package com.ampup.Ampup.controllers;

import com.ampup.Ampup.models.Playlist;
import com.ampup.Ampup.models.Song;
import com.ampup.Ampup.models.User;
import com.ampup.Ampup.models.data.PlaylistRepository;
import com.ampup.Ampup.models.data.SongRepository;
import com.ampup.Ampup.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@Controller
public class PlaylistController {

    @Autowired
    private PlaylistRepository playlistRepository;

    @Autowired
    private SongRepository songRepository;

    @Autowired
    private AuthenticationService authenticationService;

    @RequestMapping("playlist")
    public String DisplayPlaylists(HttpSession session, Model model){
        //TODO filter playlist by user
        User user=authenticationService.getUserFromSession(session);
        model.addAttribute("playlists",playlistRepository.findByOwner(user.getId()));
        return "playlist";
    }

    @GetMapping("addNewPlaylist")
    public String displayAddPlaylistForm(Model model){
        model.addAttribute("songs",songRepository.findAll());
        model.addAttribute("title","Add New Playlist");
        model.addAttribute("playlist",new Playlist());
        return "addNewPlaylist";
    }

    @PostMapping("addNewPlaylist")
    public String processAddPlaylistForm(@ModelAttribute @Valid Playlist newPlaylist,
                                         HttpSession session,
                                         @RequestParam(required=false) List<Integer> songIds,
                                         Errors errors, Model model){

        User user= authenticationService.getUserFromSession(session);

        newPlaylist.setOwner(user.getId());

        if(songIds != null){
            Iterable<Song> songsList = songRepository.findAllById(songIds);
            newPlaylist.addAllSongs(songsList);
        }
        playlistRepository.save(newPlaylist);
        model.addAttribute("playlist",playlistRepository.findAll());
        return "redirect:playlist";
    }

    @PostMapping("deletePlaylist")
    public String processDeletePlaylistForm(@RequestParam(required = false) int[] playlistIds){

        if(playlistIds != null){
            for (int id : playlistIds){
                playlistRepository.deleteById(id);
            }
        }
        return "redirect:playlist";
    }

    @GetMapping("deletePlaylist")
    public String displayDeletePlaylistForm(Model model,HttpSession session){
        User user=authenticationService.getUserFromSession(session);
        model.addAttribute("playlists",playlistRepository.findByOwner(user.getId()));
        return "deletePlaylist";
    }

    @GetMapping("viewPlaylist/{playlistId}")
    public String displayViewPlaylist(Model model, @PathVariable int playlistId,HttpSession session) {
        User user=authenticationService.getUserFromSession(session);
        Optional optPlaylist = playlistRepository.findById(playlistId);
        if (optPlaylist.isPresent()) {
            Playlist playlist = (Playlist) optPlaylist.get();
            playlist.removeDuplicates(playlist.getSongs());
            model.addAttribute("playlists", playlist);
            return "viewPlaylist";
        } else {
            return "redirect:playlist";
        }
    }
    @PostMapping("viewPlaylist/{playlistId}")
    public String processViewPlaylist(Model model, @PathVariable int playlistId,HttpSession session,@RequestParam int songId) {
        User user= authenticationService.getUserFromSession(session);
        Optional<Playlist> optPlaylist = playlistRepository.findByIdForOwner(playlistId,user.getId());
        if(optPlaylist.isPresent()){
            Playlist playlist=optPlaylist.get();
            Optional<Song> optSong=songRepository.findById(songId);
            Song song=optSong.get();
            playlist.deleteSong(song);
            playlistRepository.save(playlist);

        }
        return "redirect:/playlist";
    }


    @GetMapping("playlistSelect/{songId}")
    public String displayPlaylistSelectForm(@PathVariable int songId,HttpSession session,Model model){
        User user=authenticationService.getUserFromSession(session);
        Optional<Song> optSong=songRepository.findById(songId);
        if(optSong.isPresent()){
            Song song= optSong.get();
            model.addAttribute("song",song);
            model.addAttribute("playlists", playlistRepository.findByOwner(user.getId()));
            return "playlistSelect";
        }else{
            return "redirect:/";
        }
    }



    @PostMapping("playlistSelect/{songId}")
    public String proccessPlaylistSelectForm(@PathVariable("songId") int songId,
                                             @RequestParam(required = false) List<Integer> playlistIds,
                                             HttpSession session,Model model) {

        User user = authenticationService.getUserFromSession(session);
        Optional<Song> optSong = songRepository.findById(songId);
        if (playlistIds != null && optSong.isPresent()) {
            Song song = optSong.get();
            Iterable<Playlist> playlists = playlistRepository.findByIdAndOwner(playlistIds, user.getId());
            for (Playlist playlist : playlists) {
                playlist.addSong(song);
                playlistRepository.save(playlist);
            }
        }
        return "redirect:/";
    }
}
