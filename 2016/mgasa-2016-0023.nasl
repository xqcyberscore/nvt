# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0023.nasl 7900 2017-11-24 10:35:02Z asteins $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.131187");
script_version("$Revision: 7900 $");
script_tag(name:"creation_date", value:"2016-01-18 07:49:19 +0200 (Mon, 18 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-11-24 11:35:02 +0100 (Fri, 24 Nov 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0023");
script_tag(name: "insight", value: "A heap-based buffer overflow flaw was discovered in the way QEMU's AMD PC-Net II Ethernet Controller emulation received certain packets in loopback mode. A privileged user (with the CAP_SYS_RAWIO capability) inside a guest could use this flaw to crash the host QEMU process (resulting in denial of service) or, potentially, execute arbitrary code with privileges of the host QEMU process (CVE-2015-7504) A buffer overflow flaw was found in the way QEMU's AMD PC-Net II emulation validated certain received packets from a remote host in non-loopback mode. A remote, unprivileged attacker could potentially use this flaw to execute arbitrary code on the host with the privileges of the QEMU process. Note that to exploit this flaw, the guest network interface must have a large MTU limit (CVE-2015-7512) A NULL pointer dereference vulnerability was found in the QEMU emulator built with PCI MSI-X support. Because MSI-X MMIO support did not define the .write method, when the controller tried to write to the pending bit array(PBA) memory region, a segmentation fault occurred. A privileged attacker inside the guest could use this flaw to crash the QEMU process resulting in denial of service (CVE-2015-7549) An infinite-loop flaw was discovered in the QEMU emulator built with i8255x (PRO100) emulation support. When processing a chain of commands located in the Command Block List(CBL), each Command Block(CB) points to the next command in the list. If the link to the next CB pointed to the same block or if there was a closed loop in the chain, an infinite loop would execute the same command over and over again. A privileged user inside the guest could use this flaw to crash the QEMU instance, resulting in denial of service (CVE-2015-8345). An arithmetic-exception flaw was found in the QEMU emulator built with VNC display-driver support. The VNC server incorrectly handled 'SetPixelFormat' messages sent from clients. A privileged remote client could use this flaw to crash the guest resulting in denial of service (CVE-2015-8504). An infinite-loop issue was found in the QEMU emulator built with USB EHCI emulation support. The flaw occurred during communication between the host controller interface(EHCI) and a respective device driver. These two communicate using an isochronous transfer descriptor list(iTD). an infinite loop unfolded if there was a closed loop in the list. A privileged user inside a guest could use this flaw to consume excessive resources and cause denial of service (CVE-2015-8558). A memory-leak flaw was found in the QEMU emulator built with VMWARE VMXNET3 paravirtual NIC emulator support. The flaw occurred when a guest repeatedly tried to activate the VMXNET3 device. A privileged guest attacker could use this flaw to leak host memory, resulting in denial of service on the host. (CVE-2015-8567, CVE-2015-8568) A stack buffer-overflow vulnerability has been discovered in the QEMU emulator built with SCSI MegaRAID SAS HBA emulation support. The flaw occurs when processing the SCSI controller's CTRL_GET_INFO command. A privileged guest user could exploit this flaw to crash the QEMU process instance (denial of service). (CVE-2015-8613) An out-of-bounds write vulnerability has been found in the QEMU emulator built with Human Monitor Interface(HMP) support. The issue occurs when the 'sendkey' command (in hmp_sendkey) is processed with a 'keyname_len' that is greater than the 'keyname_buf' array size. A user or process could exploit this flaw to crash the QEMU process instance (denial of service). (CVE-2015-8619) Qemu emulator built with the Q35 chipset based pc system emulator is vulnerable to a heap based buffer overflow. It occurs during VM guest migration, as more(8 bytes) data is moved than allocated memory area. A privileged guest user could use this issue to corrupt the VM guest image, potentially leading to a DoS. This issue affects q35 machine types. (CVE-2015-8666) An out-of-bounds read-write access flaw was found in the QEMU emulator built with NE2000-device emulation support. The flaw occurred while performing 'ioport' read-write operations. A privileged (CAP_SYS_RAWIO) user or process could exploit the flaw to leak or corrupt QEMU memory bytes (CVE-2015-8743) A reachable-assertion flaw was found in the QEMU emulator built with VMWARE VMXNET3 paravirtualized NIC emulator support. The flaw occurs if a guest sends a Layer-2 packet that was smaller than 22 bytes. A privileged (CAP_SYS_RAWIO) guest user could exploit this flaw to crash the QEMU process instance, resulting in denial of service (CVE-2015-8744) A reachable-assertion flaw was found in the QEMU emulator built with VMWARE VMXNET3 paravirtualized NIC emulator support. The flaw could occur while reading Interrupt Mask Registers (IMR). A privileged (CAP_SYS_RAWIO) guest user could exploit this flaw to crash the QEMU process instance, resulting in denial of service (CVE-2015-8745) A user-after-free vulnerability was discovered in the QEMU emulator built with IDE AHCI emulation support. The flaw could occur after processing AHCI Native Command Queuing(NCQ) AIO commands. A privileged user inside the guest could use this flaw to crash the QEMU process instance (denial of service) or potentially execute arbitrary code on the host with QEMU-process privileges (CVE-2016-1568). An out-of-bounds read/write flaw was discovered in the QEMU emulator built with Firmware Configuration device emulation support. The flaw could occur while processing firmware configurations if the current configuration entry value was set to be invalid. A privileged(CAP_SYS_RAWIO) user or process inside the guest could exploit this flaw to crash the QEMU process instance (denial of service), or potentially execute arbitrary code on the host with QEMU-process privileges (CVE-2016-1714)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0023.html");
script_cve_id("CVE-2015-7504","CVE-2015-7512","CVE-2015-7549","CVE-2015-8345","CVE-2015-8504","CVE-2015-8558","CVE-2015-8567","CVE-2015-8568","CVE-2015-8613","CVE-2015-8619","CVE-2015-8666","CVE-2015-8743","CVE-2015-8744","CVE-2015-8745","CVE-2016-1568","CVE-2016-1714");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0023");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.1.3~2.11.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
