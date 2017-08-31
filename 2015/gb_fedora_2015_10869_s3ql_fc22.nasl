###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for s3ql FEDORA-2015-10869
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869735");
  script_version("$Revision: 6630 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:34:32 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-07-11 06:03:56 +0200 (Sat, 11 Jul 2015)");
  script_cve_id("CVE-2014-0485");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for s3ql FEDORA-2015-10869");
  script_tag(name: "summary", value: "Check the version of s3ql");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "S3QL is a file system that stores all its data online using storage services
like Google Storage, Amazon S3 or OpenStack. S3QL effectively provides a hard
disk of dynamic, infinite capacity that can be accessed from any computer
with Internet access.

S3QL is a standard conforming, full featured UNIX file system that is
conceptually indistinguishable from any local file system. Furthermore, S3QL
has additional features like compression, encryption, data de-duplication,
immutable trees and snapshotting which make it especially suitable for on-line
backup and archival.

S3QL is designed to favor simplicity and elegance over performance and feature-
creep. Care has been taken to make the source code as readable and serviceable
as possible. Solid error detection and error handling have been included
from the very first line, and S3QL comes with extensive automated test cases
for all its components.

== Features ==
* Transparency. Conceptually, S3QL is indistinguishable from a local file
system. For example, it supports hardlinks, symlinks, standard unix
permissions, extended attributes and file sizes up to 2 TB.

* Dynamic Size. The size of an S3QL file system grows and shrinks dynamically
as required.

* Compression. Before storage, all data may compressed with the LZMA, bzip2
or deflate (gzip) algorithm.

* Encryption. After compression (but before upload), all data can AES
encrypted with a 256 bit key. An additional SHA256 HMAC checksum is used to
protect the data against manipulation.

* Data De-duplication. If several files have identical contents, the redundant
data will be stored only once. This works across all files stored in the file
system, and also if only some parts of the files are identical while other
parts differ.
* Immutable Trees. Directory trees can be made immutable, so that their
contents can no longer be changed in any way whatsoever. This can be used to
ensure that backups can not be modified after they have been made.

* Copy-on-Write/Snapshotting. S3QL can replicate entire directory trees
without using any additional storage space. Only if one of the copies is
modified, the part of the data that has been modified will take up additional
storage space. This can be used to create intelligent snapshots that preserve
the state of a directory at different points in time using a minimum amount
of space.

* High Performance independent of network latency. All operations that do not
write or read file contents (like creating directories or moving, renaming,
and changing permissions of files and directories) are very fast because they
are carried out without any network transactions.



  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "s3ql on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-10869");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161621.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"s3ql", rpm:"s3ql~2.13~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
