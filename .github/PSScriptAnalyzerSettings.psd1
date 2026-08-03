@{
    # Which severities the analyzer reports at all. The CI step decides which of
    # them are fatal -- today Error and ParseError fail the build, Warning is
    # printed and does not. Same posture as ruff's narrow `F` + `E9` start
    # (register item 2.12): on a codebase that has never been linted, gating on
    # everything at once buries the real defects under style opinions, and the
    # thing this exists to catch is a script that does not parse.
    Severity = @('ParseError', 'Error', 'Warning')

    ExcludeRules = @(
        # The scripts write to the CI log on purpose. Write-Host is the correct
        # call for that -- Write-Output would put the text on the pipeline,
        # where callers of these functions would receive it as a return value.
        'PSAvoidUsingWriteHost',

        # run_atomic.ps1 executes rule-supplied emulation commands, which is the
        # entire point of the `custom` test type: the command comes from the
        # Sigma rule's own metadata, is reviewed with the rule, and has already
        # passed schema validation. Flagging it on every run would train us to
        # ignore the rule rather than read it.
        'PSAvoidUsingInvokeExpression',

        # Fires on verbs like Disable-/Register-/Unregister-, which these
        # helpers legitimately use. Adding ShouldProcess plumbing to internal,
        # non-exported functions that are only ever called non-interactively
        # from CI would be ceremony with no reader.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
