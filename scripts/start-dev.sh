#!/bin/bash

echo "🚀 Starting Vulnity Development Environment..."

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        return 0
    else
        return 1
    fi
}

# Check if backend is running
if check_port 8000; then
    echo "✅ Backend is running on port 8000"
else
    echo "⚠️  Backend is not running. Starting backend..."
    cd backend
    python run_server.py &
    BACKEND_PID=$!
    cd ..
    echo "🔄 Backend starting with PID: $BACKEND_PID"
fi

# Check if frontend is running
if check_port 5173; then
    echo "✅ Frontend is already running on port 5173"
else
    echo "🔄 Starting frontend..."
    cd frontend
    npm run dev &
    FRONTEND_PID=$!
    cd ..
    echo "🔄 Frontend starting with PID: $FRONTEND_PID"
fi

echo ""
echo "🌐 Application URLs:"
echo "  Frontend: http://localhost:5173"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "📝 Note: Press Ctrl+C to stop all services"

# Wait for interrupt
trap "echo '🛑 Stopping services...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT
wait
