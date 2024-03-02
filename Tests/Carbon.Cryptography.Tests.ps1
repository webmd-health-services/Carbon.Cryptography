# This test fixture is for testing that the module meets coding standards that are testable.

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    function GivenModuleImported
    {
        # Don't do anything since Initialize-Test.ps1 imports the module.
    }

    function ThenUseApprovedVerbs
    {
        param(
        )

        $verbs =
            Get-Command -Module 'WhsAutomation'|
            Where-Object { $_ -isnot [Management.Automation.AliasInfo] } |
            Select-Object -ExpandProperty Verb |
            Select-Object -Unique
        if( $verbs )
        {
            $approvedVerbs = Get-Verb | Select-Object -ExpandProperty Verb
            $verbs | Should -BeIn $approvedVerbs
        }
    }

    function ThenHelpTopic
    {
        param(
            [Parameter(Mandatory,Position=0)]
            [String]$Named,

            [Parameter(Mandatory)]
            [switch]$Exists,

            [switch]$HasSynopsis,

            [switch]$HasDescription,

            [switch]$HasExamples
        )

        $help = Get-Help -Name $Named -Full
        $help | Should -Not -BeNullOrEmpty

        if( $HasSynopsis )
        {
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        if( $HasDescription )
        {
            $help.Description | Should -Not -BeNullOrEmpty
        }

        if( $HasExamples )
        {
            $help.Examples | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Carbon.Cryptography' {
    It 'has an about help topic' {
        GivenModuleImported
        ThenHelpTopic 'about_Carbon.Cryptography' -Exists
    }

    It 'only uses approved verbs' {
        GivenModuleImported
        ThenUseApprovedVerbs
    }

    It 'has a help topic for each command' {
        GivenModuleImported
        foreach( $cmd in (Get-Command -Module 'Carbon.Cryptography' -CommandType Function,Cmdlet,Filter))
        {
            ThenHelpTopic $cmd.Name -Exists -HasSynopsis -HasDescription -HasExamples
        }
    }
}