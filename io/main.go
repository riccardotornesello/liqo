package main

import (
	"flag"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/io/ingress"
	"github.com/liqotech/liqo/io/isolation"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(networkingv1beta1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	flag.Parse()
	log.SetLogger(klog.NewKlogr())

	//----------- MANAGER
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: ":8080",
		},
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		panic(err)
	}

	//---------- INGRESS RECONCILER
	ir := ingress.NewIngressReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
	)

	if err = ir.SetupWithManager(mgr); err != nil {
		panic(err)
	}

	//---------- ISOLATION RECONCILER
	is := isolation.NewIsolationReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
	)

	if err = is.SetupWithManager(mgr); err != nil {
		panic(err)
	}

	//---------- START
	klog.Info("starting manager as controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		panic(err)
	}
}
