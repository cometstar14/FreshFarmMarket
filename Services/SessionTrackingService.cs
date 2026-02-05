using System.Collections.Concurrent;

namespace FreshFarmMarket.Services
{
    public interface ISessionTrackingService
    {
        void AddSession(string sessionId, int userId);
        void RemoveSession(string sessionId);
        bool IsUserAlreadyLoggedIn(int userId);
        int GetActiveSessionCount(int userId);
        void ClearAllUserSessions(int userId);
        bool IsSessionActive(string sessionId, int userId); // NEW METHOD - CRITICAL FOR MULTIPLE LOGIN DETECTION
    }

    public class SessionTrackingService : ISessionTrackingService
    {
        // Thread-safe dictionary: SessionId -> UserId
        private readonly ConcurrentDictionary<string, int> _activeSessions = new();

        public void AddSession(string sessionId, int userId)
        {
            _activeSessions[sessionId] = userId;
        }

        public void RemoveSession(string sessionId)
        {
            _activeSessions.TryRemove(sessionId, out _);
        }

        public bool IsUserAlreadyLoggedIn(int userId)
        {
            return _activeSessions.Values.Contains(userId);
        }

        public int GetActiveSessionCount(int userId)
        {
            return _activeSessions.Values.Count(id => id == userId);
        }

        public void ClearAllUserSessions(int userId)
        {
            var sessionsToRemove = _activeSessions
                .Where(kvp => kvp.Value == userId)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var sessionId in sessionsToRemove)
            {
                _activeSessions.TryRemove(sessionId, out _);
            }
        }

        // NEW METHOD: Check if a specific session ID is still active for a given user
        // This is the KEY to detecting when a user has logged in from another device/browser
        public bool IsSessionActive(string sessionId, int userId)
        {
            if (string.IsNullOrEmpty(sessionId))
                return false;

            // Check if session exists and belongs to the correct user
            // If the session was cleared by ClearAllUserSessions (from another login),
            // this will return false, triggering logout on the old device/browser
            return _activeSessions.TryGetValue(sessionId, out var storedUserId) && storedUserId == userId;
        }

        // For debugging/admin purposes
        public Dictionary<string, int> GetAllActiveSessions()
        {
            return _activeSessions.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }
    }
}