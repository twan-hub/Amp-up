package com.ampup.Ampup.models.data;

import com.ampup.Ampup.models.Playlist;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PlaylistRepository extends CrudRepository<Playlist,Integer> {

    public Iterable<Playlist> findByOwner(int owner);

    @Query("select p from Playlist p where p.id in ?1 and p.owner = ?2")
    public Iterable<Playlist> findByIdAndOwner(Iterable<Integer> ids, int owner);

    @Query("select p from Playlist p where p.id = ?1 and p.owner = ?2")
    public Optional<Playlist> findByIdForOwner(Integer id, Integer owner);
}
