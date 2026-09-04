# Provenance: SVEN train CWE-89 function pair from
# https://github.com/russ-lewis/ttt_-_python_cgi/commit/6096f43fd4b2d91211eec4614b7960c0816900da
# file cgi/common.py function build_board


def build_board(conn, game, size):
    board = []
    for i in range(size):
        board.append([""] * size)

    cursor = conn.cursor()
    cursor.execute("SELECT x,y,letter FROM moves WHERE gameID = %d;" % game)

    counts = {"X": 0, "O": 0}
    for move in cursor.fetchall():
        (x, y, letter) = move
        x = int(x)
        y = int(y)
        board[x][y] = letter
        counts[letter] += 1
    cursor.close()
    return (board, counts)
