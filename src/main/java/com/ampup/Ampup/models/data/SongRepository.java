package com.ampup.Ampup.models.data;

import com.ampup.Ampup.models.Song;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SongRepository extends CrudRepository<Song,Integer> {

}
