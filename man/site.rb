#!/usr/bin/env ruby

# Generate HTML site from man page sources
#
# Prerequisites
#
#   * ruby interpreter (http://www.ruby-lang.org/en/downloads/)
#   * a2x (http://www.methods.co.nz/asciidoc/INSTALL.html)
#   * zip
#
# Usage:
#
#   ruby ./man/site.rb
#
# The command above should generate file matching this shell pattern:
#
#   ./man/libcouchbase*.zip

require 'fileutils'

FileUtils.chdir(File.dirname(__FILE__))

sources = Dir.glob("man[1-9]*/*[1-9]*.txt")
destdir = "libcouchbase"
version = `git describe --always`.chomp rescue nil
if version
  destdir << "-#{version}"
end
tempdir = "tmp"
FileUtils.mkdir_p(tempdir)
FileUtils.mkdir_p(destdir)

sources.each do |file|
  contents = File.read(file)
  STDERR.print("#{file} ... ")
  tmpname = "#{tempdir}/#{File.basename(file, ".txt")}.tmp"
  tmp = File.open(tmpname, "w")
  contents.gsub!(/(?<!=\s)(((libcouchbase|lcb)\w*)\((\d+\w*)\))/, 'link:\2.\4.html[\1]')
  tmp.write(contents)
  tmp.close
  output = `a2x -D #{destdir} -L --doctype manpage --format xhtml #{tmpname} 2>&1`
  if $?.success?
    STDERR.puts("OK")
  else
    STDERR.puts("FAIL")
    STDERR.puts(output)
    exit 1
  end
  File.unlink(tmpname)
end

FileUtils.cp("#{destdir}/libcouchbase.3lib.html", "#{destdir}/index.html")
system("zip -9 -r #{File.basename(destdir)}.zip #{destdir}")
FileUtils.rm_rf(tempdir)
FileUtils.rm_rf(destdir)
