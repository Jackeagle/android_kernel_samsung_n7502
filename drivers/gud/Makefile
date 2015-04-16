#
# Makefile for the kernel mobicore drivers
#
GUD_ROOT_FOLDER := drivers/gud
# add our modules to kernel.
<<<<<<< HEAD
obj-$(CONFIG_MOBICORE_API) += mcKernelApi.o
obj-$(CONFIG_MOBICORE_SUPPORT) += mcDrvModule.o

mcDrvModule-objs := MobiCoreDriver/logging.o \
		MobiCoreDriver/ops.o \
		MobiCoreDriver/mem.o \
		MobiCoreDriver/api.o \
		MobiCoreDriver/pm.o \
		MobiCoreDriver/main.o

mcKernelApi-objs := MobiCoreKernelApi/main.o \
		MobiCoreKernelApi/clientlib.o \
		MobiCoreKernelApi/device.o \
		MobiCoreKernelApi/session.o \
		MobiCoreKernelApi/connection.o

# Release mode by default
ccflags-y := -DNDEBUG -I$(GUD_ROOT_FOLDER)
=======
obj-$(CONFIG_MOBICORE_API) += mckernelapi.o
obj-$(CONFIG_MOBICORE_SUPPORT) += mcdrvmodule.o

mcdrvmodule-objs := mobicore_driver/logging.o \
		mobicore_driver/ops.o \
		mobicore_driver/mem.o \
		mobicore_driver/api.o \
		mobicore_driver/main.o \
		mobicore_driver/pm.o

mckernelapi-objs := mobicore_kernelapi/main.o \
		mobicore_kernelapi/clientlib.o \
		mobicore_kernelapi/device.o \
		mobicore_kernelapi/session.o \
		mobicore_kernelapi/connection.o

# Release mode by default
ccflags-y := -DNDEBUG -include $(PWD)/$(GUD_ROOT_FOLDER)/mobicore_driver/build_tag.h
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
ccflags-y += -Wno-declaration-after-statement

ccflags-$(CONFIG_MOBICORE_DEBUG) += -DDEBUG
ccflags-$(CONFIG_MOBICORE_VERBOSE) += -DDEBUG_VERBOSE

# Choose one platform from the folder
<<<<<<< HEAD
MOBICORE_PLATFORM := $(shell (ls -1 $(PWD)/$(GUD_ROOT_FOLDER)/MobiCoreDriver/platforms | tail -1) )
# Use the available platform folder
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreDriver/platforms/$(MOBICORE_PLATFORM)
# MobiCore Driver includes
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreDriver/public
# MobiCore KernelApi required incldes
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreKernelApi/include
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreKernelApi/public
=======
MOBICORE_PLATFORM := $(shell (ls -1 $(PWD)/$(GUD_ROOT_FOLDER)/mobicore_driver/platforms | tail -1) )
# Use the available platform folder
ccflags-y += -I$(GUD_ROOT_FOLDER)/mobicore_driver/platforms/$(MOBICORE_PLATFORM)


ccflags-y += -I$(GUD_ROOT_FOLDER)/mobicore_driver/public
ccflags-y += -I$(GUD_ROOT_FOLDER)/mobicore_kernelapi/include
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
