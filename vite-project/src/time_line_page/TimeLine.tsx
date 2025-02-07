import { useEffect } from 'react';
import { queryDb } from '../database/db_utils';
import { useState } from 'react';


function TimeLine() {
    // Query messages from SQLite
    const [messages, setMessages] = useState([]);
    const getMessages = async () => {
        const messages = await queryDb('SELECT * FROM messages ORDER BY created_at DESC');
        return messages;
    } 
    
    useEffect(() => {
        getMessages().then((messages) => setMessages(messages));
    }, []);

    return (
        <div>
            <h1>Timeline</h1>
            <ul>
                {messages.map((msg: any) => (
                    <li key={msg.id}>
                        <strong>{msg.author}</strong>: {msg.content} <em>({msg.created_at})</em>
                    </li>
                ))}
            </ul>
        </div>
    );
}

export { TimeLine };