import { createContext, useContext } from "react";

export type UserClaim = {
    type: string;
    value: string;
}

export type AuthContextType = {
    isAuthenticated: boolean;
    claims: UserClaim[];
    user: {
        name: string;
        email: string;
        picture: string;
    }
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children, value }: { children: React.ReactNode, value: AuthContextType }) {
    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
}