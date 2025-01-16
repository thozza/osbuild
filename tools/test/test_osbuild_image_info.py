import os
import subprocess

import pytest

from osbuild.testutil import make_fake_tree
from osbuild.testutil.imports import import_module_from_path

osbuild_image_info = import_module_from_path("osbuild_image_info", "tools/osbuild-image-info")


@pytest.mark.parametrize("fake_tree,entries", (
    # no entries
    ({}, []),
    # one entry
    (
        {
            "/boot/loader/entries/0649288e52434223afde4c36460a375e-6.11.9-100.fc39.x86_64.conf": """title Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)
version 6.11.9-100.fc39.x86_64
linux /boot/vmlinuz-6.11.9-100.fc39.x86_64
initrd /boot/initramfs-6.11.9-100.fc39.x86_64.img
options root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8
grub_users $grub_users
grub_arg --unrestricted
grub_class fedora""",
        },
        [
            {
                "title": "Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)",
                "version": "6.11.9-100.fc39.x86_64",
                "linux": "/boot/vmlinuz-6.11.9-100.fc39.x86_64",
                "initrd": "/boot/initramfs-6.11.9-100.fc39.x86_64.img",
                "options": "root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8",
                "grub_users": "$grub_users",
                "grub_arg": "--unrestricted",
                "grub_class": "fedora",
            },
        ]
    ),
    # two entries
    (
        {
            "/boot/loader/entries/0649288e52434223afde4c36460a375e-6.11.9-100.fc39.x86_64.conf": """title Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)
version 6.11.9-100.fc39.x86_64
linux /boot/vmlinuz-6.11.9-100.fc39.x86_64
initrd /boot/initramfs-6.11.9-100.fc39.x86_64.img
options root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8
grub_users $grub_users
grub_arg --unrestricted
grub_class fedora""",
            "/boot/loader/entries/0649288e52434223afde4c36460a375e-6.11.9-101.fc39.x86_64.conf": """title Fedora Linux (6.11.9-101.fc39.x86_64) 39 (Thirty Nine)
version 6.11.9-101.fc39.x86_64
linux /boot/vmlinuz-6.11.9-101.fc39.x86_64
initrd /boot/initramfs-6.11.9-101.fc39.x86_64.img
options root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8
grub_users $grub_users
grub_arg --unrestricted
grub_class fedora""",
        },
        [
            {
                "title": "Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)",
                "version": "6.11.9-100.fc39.x86_64",
                "linux": "/boot/vmlinuz-6.11.9-100.fc39.x86_64",
                "initrd": "/boot/initramfs-6.11.9-100.fc39.x86_64.img",
                "options": "root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8",
                "grub_users": "$grub_users",
                "grub_arg": "--unrestricted",
                "grub_class": "fedora",
            },
            {
                "title": "Fedora Linux (6.11.9-101.fc39.x86_64) 39 (Thirty Nine)",
                "version": "6.11.9-101.fc39.x86_64",
                "linux": "/boot/vmlinuz-6.11.9-101.fc39.x86_64",
                "initrd": "/boot/initramfs-6.11.9-101.fc39.x86_64.img",
                "options": "root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8",
                "grub_users": "$grub_users",
                "grub_arg": "--unrestricted",
                "grub_class": "fedora",
            },
        ]
    ),
    # one entry with extra newlines
    (
        {
            "/boot/loader/entries/0649288e52434223afde4c36460a375e-6.11.9-100.fc39.x86_64.conf": """title Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)
version 6.11.9-100.fc39.x86_64
linux /boot/vmlinuz-6.11.9-100.fc39.x86_64
initrd /boot/initramfs-6.11.9-100.fc39.x86_64.img
options root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8
grub_users $grub_users
grub_arg --unrestricted
grub_class fedora

""",
        },
        [
            {
                "title": "Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)",
                "version": "6.11.9-100.fc39.x86_64",
                "linux": "/boot/vmlinuz-6.11.9-100.fc39.x86_64",
                "initrd": "/boot/initramfs-6.11.9-100.fc39.x86_64.img",
                "options": "root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8",
                "grub_users": "$grub_users",
                "grub_arg": "--unrestricted",
                "grub_class": "fedora",
            },
        ]
    ),
    # one entry with comments
    (
        {
            "/boot/loader/entries/0649288e52434223afde4c36460a375e-6.11.9-100.fc39.x86_64.conf": """title Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)
# this is a very useful comment
version 6.11.9-100.fc39.x86_64
linux /boot/vmlinuz-6.11.9-100.fc39.x86_64
initrd /boot/initramfs-6.11.9-100.fc39.x86_64.img
options root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8
# this is another very useful comment
grub_users $grub_users
grub_arg --unrestricted
grub_class fedora""",
        },
        [
            {
                "title": "Fedora Linux (6.11.9-100.fc39.x86_64) 39 (Thirty Nine)",
                "version": "6.11.9-100.fc39.x86_64",
                "linux": "/boot/vmlinuz-6.11.9-100.fc39.x86_64",
                "initrd": "/boot/initramfs-6.11.9-100.fc39.x86_64.img",
                "options": "root=UUID=a7e970a5-14fb-4a8a-ab09-603d1ac3fee9 ro crashkernel=auto net.ifnames=0 rhgb console=tty0 console=ttyS0,115200n8",
                "grub_users": "$grub_users",
                "grub_arg": "--unrestricted",
                "grub_class": "fedora",
            },
        ]
    ),
))
def test_read_boot_entries(tmp_path, fake_tree, entries):
    make_fake_tree(tmp_path, fake_tree)
    assert osbuild_image_info.read_boot_entries(tmp_path / "boot") == entries


def make_fake_iso(iso_tree, output_dir) -> str:
    iso_path = os.path.join(output_dir, "image.iso")
    subprocess.run(["mkisofs", "-o", iso_path, "-R", "-J", iso_tree], check=True)
    return iso_path


@pytest.mark.skipif(os.getuid() != 0, reason="root only")
def test_analyse_iso_fail_mount(tmp_path):
    # fake ISO that can't be mounted
    image_path = tmp_path / "image.iso"
    image_path.touch()

    with pytest.raises(
            subprocess.CalledProcessError,
            match=fr"^Command '\['mount', '\-o', 'ro,loop', PosixPath\('{image_path}'\)"):
        osbuild_image_info.analyse_iso(image_path)


@pytest.mark.skipif(os.getuid() != 0, reason="root only")
def test_analyse_iso_fail_no_tarball(tmp_path):
    # ISO that can be mounted, but doesn't contain the liveimg.tar.gz
    iso_tree = tmp_path / "iso_tree"
    iso_tree.mkdir()
    image_path = make_fake_iso(iso_tree, tmp_path)

    with pytest.raises(
            RuntimeError,
            match=f"^Failed to find liveimg.tar.gz in ISO: {image_path}$"):
        osbuild_image_info.analyse_iso(image_path)
