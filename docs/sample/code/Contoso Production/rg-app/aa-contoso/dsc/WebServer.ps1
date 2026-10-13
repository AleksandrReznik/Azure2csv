Configuration WebServer {
    Node localhost { WindowsFeature IIS { Ensure = 'Present'; Name = 'Web-Server' } }
}
