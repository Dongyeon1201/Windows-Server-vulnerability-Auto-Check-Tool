#rename *.zip -> *.docx
Rename-Item -Path ($args[0] + "\Result_Report.docx.zip") ($args[0] + "\Result_Report.docx")

################################# convert PDF #######################################

$word_app = New-Object -ComObject Word.Application

# word document -> pdf document
Get-ChildItem -Path $args[0] -Filter *.doc? | ForEach-Object {

    $document = $word_app.Documents.Open($_.FullName)

    $pdf_filename = "$($_.DirectoryName)\$($_.BaseName).pdf"

    $document.SaveAs([ref] $pdf_filename, [ref] 17)

    $document.Close()
}

$word_app.Quit()

############################## Remove not pdf file ###################################
Remove-Item ($args[0] + "\temp") -Recurse -Force
Remove-Item ($args[0] + "\check_document_form.docx.zip") -Recurse -Force
Remove-Item ($args[0] + "\*.txt") -Force
Remove-Item ($args[0] + "\*.docx") -Force