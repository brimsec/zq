SELECT people.nameFirst, people.nameLast, batting.HR, teams.name
FROM BATTING batting
  JOIN PEOPLE people
    ON batting.playerID = people.playerID
  JOIN TEAMS teams
    ON batting.teamID = teams.teamID
WHERE batting.yearID = 1977 AND teams.yearID = 1977
ORDER BY batting.HR DESC
LIMIT 10
