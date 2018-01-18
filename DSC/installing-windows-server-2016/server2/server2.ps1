Configuration Server2
{
    Node "server2" {

        WindowsFeature DHCPServer {
            Ensure = "Present"
            Name = "DHCP"
        }
    }
}

Server2
Start-DscConfiguration -Wait -Force -Path .\Server2 -Verbose