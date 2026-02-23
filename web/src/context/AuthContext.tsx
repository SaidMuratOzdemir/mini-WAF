import { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import * as React from "react";
import { fetchCurrentUser } from '../api/auth';

interface AuthContextType {
    isAuthenticated: boolean;
    role: 'admin' | 'super_admin' | null;
    logout: () => void;
    checkAuth: () => boolean;
    refreshCurrentUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [role, setRole] = useState<'admin' | 'super_admin' | null>(null);
    const navigate = useNavigate();

    const checkAuth = () => {
        const token = localStorage.getItem('token');
        return !!token;
    };

    const refreshCurrentUser = async () => {
        const token = localStorage.getItem('token');
        if (!token) {
            setRole(null);
            setIsAuthenticated(false);
            return;
        }

        try {
            const me = await fetchCurrentUser();
            setRole(me.role);
            setIsAuthenticated(true);
        } catch {
            localStorage.removeItem('token');
            setRole(null);
            setIsAuthenticated(false);
        }
    };

    useEffect(() => {
        void refreshCurrentUser();
    }, []);

    const logout = () => {
        localStorage.removeItem('token');
        setIsAuthenticated(false);
        setRole(null);
        navigate('/login');
    };

    return (
        <AuthContext.Provider value={{ isAuthenticated, role, logout, checkAuth, refreshCurrentUser }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}
