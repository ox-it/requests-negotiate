# Create then rename a ForeignKey when migrating

A minimal testcase for when one uses AddField to create a ForeignKey, then
RenameField within the same migration. Django's migrations seem to try to
create the attendant contraint and index with the old field name.
