package models

import corev1 "k8s.io/api/core/v1"

type PodLogOptions struct {
	Container string
	TailLines int64
}

func (o PodLogOptions) ToKube() *corev1.PodLogOptions {
	var tail *int64
	if o.TailLines > 0 {
		value := o.TailLines
		tail = &value
	}
	return &corev1.PodLogOptions{
		Follow:    true,
		Container: o.Container,
		TailLines: tail,
	}
}
