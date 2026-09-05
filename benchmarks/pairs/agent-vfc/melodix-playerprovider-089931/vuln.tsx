// Provenance: alexshao3/melodix  (vuln).
// repo: alexshao3/melodix
// commit: c074fc7413338aefcbea3170ef4d3ba486a8a4b7
// parent: c074fc7413338aefcbea3170ef4d3ba486a8a4b7
// commit_url: https://github.com/alexshao3/melodix/commit/089931ef71ea1e5b7586520baf1a5498e2f05b13
// cve: 
// license: MIT
// function: PlayerProvider
// relpath: apps/miniapp/src/components/PlayerProvider.tsx
// provenance: agent
// mechanism: permissive_default

export function PlayerProvider({ children }: { children: React.ReactNode }) {
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [currentTrack, setCurrentTrack] = useState<Track | null>(null);
  const [queue, setQueue] = useState<Track[]>([]);
  const [history, setHistory] = useState<Track[]>([]);
  const [isPlaying, setIsPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  const handleEndedRef = useRef<() => void>(() => {});

  useEffect(() => {
    const a = new Audio();
    a.crossOrigin = 'anonymous';
    a.preload = 'metadata';
    audioRef.current = a;
    const t = () => setPosition(a.currentTime);
    const l = () => setDuration(a.duration || 0);
    const p = () => setIsPlaying(true);
    const ps = () => setIsPlaying(false);
    const e = () => handleEndedRef.current?.();
    a.addEventListener('timeupdate', t);
    a.addEventListener('loadedmetadata', l);
    a.addEventListener('play', p);
    a.addEventListener('pause', ps);
    a.addEventListener('ended', e);
    return () => {
      a.pause();
      a.removeEventListener('timeupdate', t);
      a.removeEventListener('loadedmetadata', l);
      a.removeEventListener('play', p);
      a.removeEventListener('pause', ps);
      a.removeEventListener('ended', e);
    };
  }, []);

  const playTrack = useCallback((t: Track) => {
    const a = audioRef.current;
    if (!a) return;
    a.src = t.streamUrl ?? t.audioUrl;
    setCurrentTrack(t);
    setPosition(0);
    pushRecentlyPlayed(t);
    // Best-effort server-side history mirror; `recordPlay` no-ops for guests.
    void api.recordPlay(t.id);
    a.play().catch(() => undefined);
  }, []);

  const play = useCallback(
    (track: Track, newQueue?: Track[]) => {
      tgHaptic('light');
      if (newQueue) {
        const idx = newQueue.findIndex((t) => t.id === track.id);
        const upcoming =
          idx >= 0 ? newQueue.slice(idx + 1) : newQueue.filter((t) => t.id !== track.id);
        setQueue(upcoming);
      }
      if (currentTrack && currentTrack.id !== track.id) {
        setHistory((h) => [...h.slice(-19), currentTrack]);
      }
      playTrack(track);
    },
    [currentTrack, playTrack],
  );

  const toggle = useCallback(() => {
    const a = audioRef.current;
    if (!a || !currentTrack) return;
    tgHaptic('light');
    if (a.paused) a.play();
    else a.pause();
  }, [currentTrack]);

  const next = useCallback(() => {
    if (queue.length === 0) return;
    const [head, ...rest] = queue;
    if (!head) return;
    if (currentTrack) setHistory((h) => [...h.slice(-19), currentTrack]);
    setQueue(rest);
    playTrack(head);
  }, [queue, currentTrack, playTrack]);

  const prev = useCallback(() => {
    const a = audioRef.current;
    if (a && a.currentTime > 3) {
      a.currentTime = 0;
      return;
    }
    const last = history[history.length - 1];
    if (!last) {
      if (a) a.currentTime = 0;
      return;
    }
    setHistory((h) => h.slice(0, -1));
    if (currentTrack) setQueue((q) => [currentTrack, ...q]);
    playTrack(last);
  }, [history, currentTrack, playTrack]);

  useEffect(() => {
    handleEndedRef.current = () => next();
  }, [next]);

  const seek = useCallback((s: number) => {
    const a = audioRef.current;
    if (!a) return;
    a.currentTime = s;
    setPosition(s);
  }, []);

  const value = useMemo(
    () => ({ currentTrack, queue, isPlaying, position, duration, play, toggle, next, prev, seek }),
    [currentTrack, queue, isPlaying, position, duration, play, toggle, next, prev, seek],
  );

  return <PlayerContext.Provider value={value}>{children}</PlayerContext.Provider>;
}
