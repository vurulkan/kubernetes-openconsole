package models

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodLogOptions struct {
	Container string
	TailLines int64
	Previous  bool      // the previous (crashed) container instance; not followed, it has ended
	SinceTime time.Time // resume after a drop; replaces TailLines
}

// ToKube always asks for timestamps: the viewer resumes from the last one it saw.
func (o PodLogOptions) ToKube() *corev1.PodLogOptions {
	opts := &corev1.PodLogOptions{
		Follow:     !o.Previous,
		Previous:   o.Previous,
		Container:  o.Container,
		Timestamps: true,
	}
	if !o.SinceTime.IsZero() {
		opts.SinceTime = &metav1.Time{Time: o.SinceTime}
	} else if o.TailLines > 0 {
		value := o.TailLines
		opts.TailLines = &value
	}
	return opts
}
