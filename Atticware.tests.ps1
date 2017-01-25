#Test module to retrieve data from a test tenant

#Make sure we are in the coirrect location
cd C:\Users\josverl\OneDrive\PowerShell\Dev\AADGraph

#Load the Module under Test 
Import-Module .\AADGraph.psd1 -Force

#Setup test account and connect to the tenant 


Describe "AADGraph : tenant test" {
    
    BeforeAll { 
        $cred = Get-StoredCredential -target admin@atticware.onmicrosoft.com
        $tenant = 'atticware.onmicrosoft.com'

        #        $cred = Get-StoredCredential -target admin@jvdemo3.onmicrosoft.com
        #        $tenant = 'jvdemo3.onmicrosoft.com'
    }
    

    it "Connect to tenant $tenant" {

        {Connect-AADGraph -tenant $tenant -Credentials $cred  }  | Should not Throw    
    }

    Context 'Object paging 10' { 
        it "gets first page of Objects" { {$Script:Users_P1 = Get-AADGraphObject -Type 'users'  -PageSize 10 }| Should not throw
            $Script:Users_P1.Count | Should be 10
        }

        it "gets Next page of Objects " { {$Script:Users_P2 = Get-AADGraphObject -Type 'users' -Next -PageSize 10}| Should not throw
            $Script:Users_P2.Count | Should be 10
        }

        it "check 2nd page content" {
            #Check if the page are indeed different
            0..($Script:Users_P2.Count -1) | %{ 
                $Users_P1[$_].userPrincipalName | Should not be  $Users_P2[$_].userPrincipalName
            }
        }
    }

    Context 'Object paging default' { 

<<<<<<< HEAD
        it "gets first page of Objects" { {$Script:Users_P1 = Get-AADGraphObject -Type 'users'   }| Should not throw
            $Script:Users_P1.Count | Should be 100
        }

        it "gets Next page of Objects " { {$Script:Users_P2 = Get-AADGraphObject -Type 'users' -Next }| Should not throw
=======
        it "gets first page of Objects" { {$Script:Users_P1 = Get-AADGraphObject -Type 'users'   }| Should not throw
            $Script:Users_P1.Count | Should be 100
        }

        it "gets Next page of Objects " { {$Script:Users_P2 = Get-AADGraphObject -Type 'users' -Next }| Should not throw
>>>>>>> 37c206d3d98850c995a601b37287e479de18b62a
            $Script:Users_P2.Count | Should be 100
        }
        it "check 2nd page content" {
            #Check if the page are indeed different
            0..($Script:Users_P2.Count -1) | %{ 
                $Users_P1[$_].userPrincipalName | Should not be  $Users_P2[$_].userPrincipalName
            }
        }
    }

    Context 'User paging'  { 

<<<<<<< HEAD
        it "gets first page of users" { {$Script:Users_P1 = Get-AADGraphUser }| Should not throw
            $Script:Users_P1.Count | Should be 100
        }

        it "gets Next page of users " { {$Script:Users_P2 = Get-AADGraphUser -Next}| Should not throw
=======
        it "gets first page of users" { {$Script:Users_P1 = Get-AADGraphUser }| Should not throw
            $Script:Users_P1.Count | Should be 100
        }

        it "gets Next page of users " { {$Script:Users_P2 = Get-AADGraphUser -Next}| Should not throw
>>>>>>> 37c206d3d98850c995a601b37287e479de18b62a
            $Script:Users_P2.Count | Should be 100
        }
        it "get-user remembers the page location beween calls" {
            #Check if the page are indeed different
            0..($Script:Users_P2.Count -1) | %{ 
                $Users_P1[$_].userPrincipalName | Should not be  $Users_P2[$_].userPrincipalName
            }
        }
    }
}

