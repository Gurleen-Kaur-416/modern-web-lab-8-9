"use client";

import { useState, type FormEvent } from "react";
import Alert from "@/components/feedback/Alert";

interface LoginFormProps {
  onSubmit: (username: string, password: string) => Promise<void>;
}

export default function LoginForm({ onSubmit }: LoginFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    try {
      await onSubmit(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    }
  }

  return (
    <form onSubmit={handleSubmit} className="auth-form">
      <div>
        <label htmlFor="username">Username</label>
        <input
          id="username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          placeholder="Enter username"
        />
      </div>

      <div>
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="Enter password"
        />
      </div>

      {error ? <Alert variant="error" message={error} /> : null}

      <button className="btn btn-primary" type="submit">
        Sign in
      </button>
    </form>
  );
}